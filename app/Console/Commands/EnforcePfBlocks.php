<?php

namespace App\Console\Commands;

use App\Services\Detection\MacPfEnforcer;
use App\Services\WafSyncService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

/**
 * Tail Suricata's eve.json for drop / high-severity alert events and
 * install pf blocks for their source IPs. Run on a loop by the watchdog.
 *
 * No-op on non-macOS platforms (Linux/Windows have inline IPS support).
 */
class EnforcePfBlocks extends Command
{
    protected $signature = 'ids:pf-enforce
        {--eve=/var/log/suricata/eve.json : eve.json path}
        {--limit=2000 : Max new events processed per invocation}
        {--ttl=3600 : Block TTL in seconds}';

    protected $description = 'Enforce Suricata drop events via pf (macOS reactive IPS)';

    public function handle(MacPfEnforcer $pf, WafSyncService $waf): int
    {
        if (!$pf->isSupported()) {
            $this->info('pf-enforce: not supported on this platform, skipping');
            return 0;
        }

        // Gate: only enforce when the Hub has explicitly enabled IPS mode.
        // `ips_enabled` is the top-level feature flag (Hub UI "Enable IPS"
        // button) and `addons.suricata_mode` must be 'ips'. Both must be true
        // — either one alone is treated as detection-only. When the Hub
        // flips back to 'ids' we stop adding blocks, but intentionally do
        // NOT disable pf or flush the table (existing time-boxed blocks
        // still age out via pruneExpired within TTL).
        $cfg = $waf->getWafConfig();
        $ipsEnabled = ($cfg['ips_enabled'] ?? false) === true;
        $mode = $cfg['addons']['suricata_mode'] ?? 'ids';
        if (!$ipsEnabled || $mode !== 'ips') {
            $this->info(sprintf(
                'pf-enforce: disabled (ips_enabled=%s suricata_mode=%s), skipping',
                var_export($ipsEnabled, true), $mode
            ));
            // Still prune so any existing blocks age out even while disabled.
            $pruned = $pf->pruneExpired();
            if ($pruned > 0) $this->info("pf-enforce: pruned {$pruned} expired block(s)");
            return 0;
        }

        // IPS is on — make sure pf kernel is enabled so our anchor actually
        // drops packets. No-op if already enabled.
        // Do NOT auto-enable pf. If pf is off, blocks silently no-op.
        // Operator must explicitly `sudo pfctl -ef /etc/pf.conf` when
        // they're confident the setup is safe. Three outages taught us
        // that auto-enable + stale block tables = bricked connectivity.
        $pfStatus = $pf->status();
        if (!$pfStatus['pf_enabled']) {
            $this->info('pf-enforce: pf kernel disabled (operator must enable manually), skipping');
            return 0;
        }

        // Reconcile: flush pf table then re-add only valid (non-expired)
        // entries from state. Prevents stale blocks from old code or
        // crashed state from persisting across code updates.
        $pf->reconcileTable();

        $evePath = $this->option('eve');
        if (!file_exists($evePath)) {
            $this->info("pf-enforce: eve.json not found at {$evePath}");
            return 0;
        }

        $posFile = storage_path('app/suricata_enforce_position.txt');
        clearstatcache(true, $evePath);
        $size = filesize($evePath);

        // First run on this agent (no position file yet): start from the
        // END of eve.json, not the beginning. Otherwise we replay the
        // entire history — potentially GiB of stats/flow/alert events —
        // at 2000-line-per-tick throughput and the live log write rate
        // keeps us permanently behind the tail, so real attacks never
        // get enforced. Only events appended after IPS activation count.
        if (!file_exists($posFile)) {
            $lastPos = $size;
            @file_put_contents($posFile, (string) $lastPos);
            $this->info("pf-enforce: first run, seeking to eve.json tail ({$size} bytes)");
        } else {
            $lastPos = (int) file_get_contents($posFile);
        }

        // Handle log rotation / truncation
        if ($size < $lastPos) $lastPos = 0;

        // Catch-up guard: if we've fallen more than this many bytes behind
        // the tail (e.g. sync daemon paused for hours, agent restarted
        // after a long offline), don't try to crawl through the backlog —
        // jump to tail. The backlog is old info anyway; enforcing it now
        // would block long-gone connections and waste cycles.
        $maxLag = 16 * 1024 * 1024;  // 16 MiB
        if ($size - $lastPos > $maxLag) {
            $this->warn(sprintf(
                'pf-enforce: %d MiB behind tail, skipping backlog',
                ($size - $lastPos) >> 20
            ));
            $lastPos = $size;
            @file_put_contents($posFile, (string) $lastPos);
            return 0;
        }

        $fh = @fopen($evePath, 'r');
        if (!$fh) {
            $this->error("pf-enforce: cannot open {$evePath}");
            return 1;
        }
        fseek($fh, $lastPos);

        $limit = max(1, (int) $this->option('limit'));
        $ttl = max(60, (int) $this->option('ttl'));

        $scanned = 0;
        $blocked = 0;
        $seenThisRun = [];  // dedupe within a run

        while (!feof($fh) && $scanned < $limit) {
            $line = fgets($fh);
            if ($line === false) break;
            $scanned++;

            $entry = @json_decode($line, true);
            if (!is_array($entry)) continue;

            $type = $entry['event_type'] ?? '';

            // ONLY enforce `event_type: drop`. Previously we also blocked
            // alert events at severity <= 2, but Suricata's ET Open rules
            // fire sev-2 on NORMAL CDN/DNS/cloud traffic (Google 142.250.*,
            // Cloudflare 162.159.*, Apple 17.253.*, even 8.8.8.8 DNS).
            // Auto-blocking those bricked the Mac's entire connectivity.
            //
            // On macOS pcap mode, Suricata almost never emits event_type:drop
            // (drop rules run as alert). So this path only fires when:
            //   - Hub-side custom rules specifically set `drop` action, or
            //   - Future inline mode (NFQUEUE/divert) becomes available, or
            //   - Operator manually injects test events.
            //
            // For alert-based blocking, the Hub should maintain a curated
            // blocklist pushed via the blocked_ips config, not the agent
            // auto-blocking from noisy ET signature matches.
            if ($type !== 'drop') continue;

            $src = $entry['src_ip'] ?? null;
            if (!$src || isset($seenThisRun[$src])) continue;
            $seenThisRun[$src] = true;

            if ($pf->blockIp($src, $ttl)) {
                $blocked++;
            }
        }

        $pos = ftell($fh);
        fclose($fh);
        @file_put_contents($posFile, (string) $pos);

        $pruned = $pf->pruneExpired();

        $this->info(sprintf(
            'pf-enforce: scanned=%d blocked=%d pruned=%d live_table=%d',
            $scanned, $blocked, $pruned, $pf->liveTableSize()
        ));

        if ($blocked > 0 || $pruned > 0) {
            Log::info('[PF] enforce cycle', [
                'scanned' => $scanned,
                'blocked' => $blocked,
                'pruned'  => $pruned,
                'live'    => $pf->liveTableSize(),
            ]);
        }
        return 0;
    }
}
