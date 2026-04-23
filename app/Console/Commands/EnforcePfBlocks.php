<?php

namespace App\Console\Commands;

use App\Services\Detection\MacPfEnforcer;
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
        {--ttl=3600 : Block TTL in seconds}
        {--min-severity=2 : Minimum Suricata alert severity to block (1=critical, 2=high)}';

    protected $description = 'Enforce Suricata drop events via pf (macOS reactive IPS)';

    public function handle(MacPfEnforcer $pf): int
    {
        if (!$pf->isSupported()) {
            $this->info('pf-enforce: not supported on this platform, skipping');
            return 0;
        }

        $evePath = $this->option('eve');
        if (!file_exists($evePath)) {
            $this->info("pf-enforce: eve.json not found at {$evePath}");
            return 0;
        }

        $posFile = storage_path('app/suricata_enforce_position.txt');
        $lastPos = file_exists($posFile) ? (int) file_get_contents($posFile) : 0;
        clearstatcache(true, $evePath);
        $size = filesize($evePath);

        // Handle log rotation / truncation
        if ($size < $lastPos) $lastPos = 0;

        $fh = @fopen($evePath, 'r');
        if (!$fh) {
            $this->error("pf-enforce: cannot open {$evePath}");
            return 1;
        }
        fseek($fh, $lastPos);

        $limit = max(1, (int) $this->option('limit'));
        $ttl = max(60, (int) $this->option('ttl'));
        $minSev = max(1, (int) $this->option('min-severity'));

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
            if ($type !== 'drop' && $type !== 'alert') continue;

            // drop events always enforce. alert events only if severity is
            // high enough (Suricata sev 1=critical, 2=high, 3=medium).
            $shouldBlock = $type === 'drop';
            if ($type === 'alert') {
                $sev = (int) ($entry['alert']['severity'] ?? 3);
                $shouldBlock = $sev <= $minSev;
            }
            if (!$shouldBlock) continue;

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
