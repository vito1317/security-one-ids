<?php

namespace App\Services\Detection;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Process;

/**
 * macOS reactive IPS via pf (packet filter).
 *
 * Suricata on macOS can only run in pcap passive mode (no NFQUEUE/WinDivert
 * equivalent), so rule `drop` actions are detection-only — they just write
 * to eve.json without actually dropping packets. This class closes that gap
 * by reading those drop events and installing real kernel-level blocks via
 * pf for the offending source IPs.
 *
 * The pf setup uses a dedicated anchor ("security-one-ids") with a table
 * ("ids_block"). Entries are TTL'd in a state file and periodically pruned
 * so blocks don't accumulate forever.
 *
 * Limitations:
 *   - Reactive, not inline. The first packet of a malicious flow is already
 *     on the host before Suricata sees it and adds the block.
 *   - Source-IP granularity only. Cannot distinguish per-port or per-payload.
 *   - Attackers can evade by rotating source IPs (a limitation shared by
 *     every IP-based blocker).
 */
class MacPfEnforcer
{
    public const ANCHOR_NAME = 'security-one-ids';
    public const TABLE_NAME  = 'ids_block';
    public const ANCHOR_FILE = '/etc/pf.anchors/security-one-ids';

    private const STATE_FILE = 'app/pf_blocked_ips.json';
    private const DEFAULT_TTL = 3600;

    public function isSupported(): bool
    {
        return PHP_OS === 'Darwin' && is_executable('/sbin/pfctl');
    }

    /**
     * Add an IP to the pf block table. Idempotent.
     */
    public function blockIp(string $ip, int $ttlSeconds = self::DEFAULT_TTL): bool
    {
        if (!$this->isSupported())       return false;
        if (!$this->isRoutableIp($ip))   return false;
        if ($this->isSelfOrLoopback($ip)) return false;

        try {
            $cmd = sprintf(
                '/sbin/pfctl -a %s -t %s -T add %s 2>&1',
                escapeshellarg(self::ANCHOR_NAME),
                escapeshellarg(self::TABLE_NAME),
                escapeshellarg($ip)
            );
            $result = Process::timeout(5)->run($cmd);
            if ($result->exitCode() !== 0) {
                Log::warning('[PF] pfctl add failed', [
                    'ip' => $ip,
                    'output' => trim($result->output() . $result->errorOutput()),
                ]);
                return false;
            }
            $this->recordBlock($ip, $ttlSeconds);
            Log::info('[PF] Blocked IP', ['ip' => $ip, 'ttl' => $ttlSeconds]);
            return true;
        } catch (\Throwable $e) {
            Log::warning('[PF] blockIp exception', ['ip' => $ip, 'err' => $e->getMessage()]);
            return false;
        }
    }

    public function unblockIp(string $ip): bool
    {
        if (!$this->isSupported()) return false;
        try {
            $cmd = sprintf(
                '/sbin/pfctl -a %s -t %s -T delete %s 2>&1',
                escapeshellarg(self::ANCHOR_NAME),
                escapeshellarg(self::TABLE_NAME),
                escapeshellarg($ip)
            );
            Process::timeout(5)->run($cmd);
            $this->removeFromState($ip);
            return true;
        } catch (\Throwable $e) {
            Log::warning('[PF] unblockIp exception', ['ip' => $ip, 'err' => $e->getMessage()]);
            return false;
        }
    }

    /**
     * Remove entries whose TTL has passed. Returns count removed.
     */
    public function pruneExpired(): int
    {
        if (!$this->isSupported()) return 0;
        $state = $this->loadState();
        $now = time();
        $removed = 0;
        foreach ($state as $ip => $expiresAt) {
            if ($expiresAt > 0 && $expiresAt < $now) {
                if ($this->unblockIp($ip)) $removed++;
            }
        }
        return $removed;
    }

    /** @return array<string,int>  ip => expires_at (unix timestamp) */
    public function listBlocked(): array
    {
        return $this->loadState();
    }

    /**
     * Live count of entries actually in the kernel pf table. Returns -1 if
     * the anchor isn't loaded.
     */
    public function liveTableSize(): int
    {
        if (!$this->isSupported()) return -1;
        try {
            $cmd = sprintf(
                '/sbin/pfctl -a %s -t %s -T show 2>/dev/null | wc -l',
                escapeshellarg(self::ANCHOR_NAME),
                escapeshellarg(self::TABLE_NAME)
            );
            $result = Process::timeout(5)->run($cmd);
            if ($result->exitCode() !== 0) return -1;
            return (int) trim($result->output());
        } catch (\Throwable $e) {
            return -1;
        }
    }

    /**
     * Ensure pf is enabled at the kernel level and the anchor is loaded.
     * No-op if already enabled; re-applies /etc/pf.conf if not. Returns
     * true iff pf is Status: Enabled afterwards.
     *
     * Called by ids:pf-enforce on first tick after the Hub flips
     * ips_enabled=true + suricata_mode=ips. We do NOT disable pf when the
     * Hub flips back to ids — operator-owned pf rules (com.apple anchors
     * etc.) might still depend on it. The enforcer simply stops adding
     * new entries; existing time-boxed blocks age out via pruneExpired.
     */
    public function ensurePfEnabled(): bool
    {
        if (!$this->isSupported()) return false;
        try {
            $r = Process::timeout(5)->run('/sbin/pfctl -s info 2>&1');
            if ($r->exitCode() === 0 && str_contains($r->output(), 'Status: Enabled')) {
                return true;
            }
            Log::info('[PF] pf kernel is disabled; enabling and loading /etc/pf.conf');
            // Load the ruleset (which includes our anchor) and enable.
            Process::timeout(5)->run('/sbin/pfctl -f /etc/pf.conf 2>&1');
            Process::timeout(5)->run('/sbin/pfctl -e 2>&1');
            $r = Process::timeout(5)->run('/sbin/pfctl -s info 2>&1');
            $enabled = $r->exitCode() === 0 && str_contains($r->output(), 'Status: Enabled');
            if ($enabled) {
                Log::info('[PF] pf kernel enabled');
            } else {
                Log::warning('[PF] pfctl -e did not stick', [
                    'out' => trim($r->output() . $r->errorOutput()),
                ]);
            }
            return $enabled;
        } catch (\Throwable $e) {
            Log::warning('[PF] ensurePfEnabled exception: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Check that the pf anchor file exists, the anchor is loaded in the
     * running ruleset, and pf itself is enabled. Returns a diagnostic array.
     */
    public function status(): array
    {
        $s = [
            'supported'     => $this->isSupported(),
            'anchor_file'   => file_exists(self::ANCHOR_FILE),
            'pf_enabled'    => false,
            'anchor_loaded' => false,
            'table_size'    => -1,
        ];
        if (!$s['supported']) return $s;
        try {
            $r = Process::timeout(5)->run('/sbin/pfctl -s info 2>&1');
            $s['pf_enabled'] = str_contains($r->output(), 'Status: Enabled');
        } catch (\Throwable $e) {}
        try {
            $r = Process::timeout(5)->run('/sbin/pfctl -s Anchors 2>&1');
            $s['anchor_loaded'] = str_contains($r->output(), self::ANCHOR_NAME);
        } catch (\Throwable $e) {}
        $s['table_size'] = $this->liveTableSize();
        return $s;
    }

    // ------------------------------------------------------------------
    //  helpers
    // ------------------------------------------------------------------

    private function isRoutableIp(string $ip): bool
    {
        return (bool) filter_var($ip, FILTER_VALIDATE_IP);
    }

    /**
     * Return true for any IP we refuse to block.
     *
     * Defense-in-depth: the host's own IPs are discovered dynamically via
     * ifconfig as a best-effort check, but that lookup can fail (DHCP not
     * yet assigned, timeout, Process::run quirks, multi-interface setups).
     * A self-IP false-negative bricks LAN connectivity — we saw this in
     * production: 192.168.50.77 (the host) was added to the pf drop table
     * because ifconfig detection missed it, and Claude/web all went dark
     * until the user rebooted.
     *
     * So we ALSO hard-skip the RFC 1918 private ranges, loopback, link-
     * local, and multicast unconditionally. The enforcer is for blocking
     * external attackers — LAN traffic should never hit this path. If a
     * corporate deployment really needs to block a LAN host, do it via
     * pfctl directly, not through auto-enforcement from IDS events.
     */
    private function isSelfOrLoopback(string $ip): bool
    {
        // Fast-path: loopback / unspecified / IPv6 link-local / multicast
        if (str_starts_with($ip, '127.'))  return true;
        if ($ip === '0.0.0.0')             return true;
        if (str_starts_with($ip, '::'))    return true;
        if (str_starts_with($ip, 'fe80:')) return true;
        if (str_starts_with($ip, 'ff'))    return true;

        // Reject any non-globally-routable IPv4 address. filter_var with
        // FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE returns
        // false for RFC 1918 (10/8, 172.16/12, 192.168/16), link-local
        // 169.254/16, loopback 127/8, and other reserved ranges. If it
        // *fails* that filter it's a private/reserved IP -> skip.
        $global = filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        );
        if ($global === false) {
            return true;
        }

        // Last line of defense: still try to detect the host's own public
        // IPs (ifconfig). We already filtered RFC 1918 above so this only
        // matters if the host has a globally routable IP directly bound
        // (rare on LAN, common on cloud VMs). Cache per process.
        static $ownIps = null;
        if ($ownIps === null) {
            $ownIps = [];
            try {
                $r = Process::timeout(3)->run("ifconfig 2>/dev/null | awk '/inet /{print \$2}'");
                foreach (explode("\n", $r->output()) as $line) {
                    $line = trim($line);
                    if ($line !== '') $ownIps[$line] = true;
                }
            } catch (\Throwable $e) {}
        }
        return isset($ownIps[$ip]);
    }

    private function recordBlock(string $ip, int $ttlSeconds): void
    {
        $state = $this->loadState();
        $state[$ip] = time() + $ttlSeconds;
        $this->saveState($state);
    }

    private function removeFromState(string $ip): void
    {
        $state = $this->loadState();
        unset($state[$ip]);
        $this->saveState($state);
    }

    /** @return array<string,int> */
    private function loadState(): array
    {
        $path = storage_path(self::STATE_FILE);
        if (!file_exists($path)) return [];
        $raw = @file_get_contents($path);
        if ($raw === false) return [];
        $decoded = @json_decode($raw, true);
        return is_array($decoded) ? $decoded : [];
    }

    private function saveState(array $state): void
    {
        $path = storage_path(self::STATE_FILE);
        $dir = dirname($path);
        if (!is_dir($dir)) @mkdir($dir, 0755, true);
        $tmp = $path . '.new';
        @file_put_contents($tmp, json_encode($state, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT), LOCK_EX);
        @rename($tmp, $path);
    }
}
