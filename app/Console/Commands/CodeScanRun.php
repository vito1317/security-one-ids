<?php

namespace App\Console\Commands;

use App\Services\CodeScanService;
use App\Services\ComplianceAnalyzer;
use App\Services\WafSyncService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

/**
 * Run the program-code vulnerability scan on its own and upload the result
 * as a compliance report (embedded under `code_scan`). Useful for cron or
 * ad-hoc runs, and dispatched by the heartbeat handler when the Hub sets
 * `addons.code_scan_now`.
 */
class CodeScanRun extends Command
{
    protected $signature = 'code-scan:run
        {--no-send : Do not POST the result to the WAF Hub}
        {--format=table : Output format (table|json)}
        {--out= : Optional path to write the full JSON report}';

    protected $description = 'Run SAST / AI program-code vulnerability scan and report findings to the WAF Hub';

    public function handle(
        CodeScanService $codeScan,
        ComplianceAnalyzer $analyzer,
        WafSyncService $waf,
    ): int {
        $this->info('🔬 Running program-code vulnerability scan…');
        $cs = $codeScan->run();

        if (empty($cs['enabled'])) {
            $this->warn('⚠️  Code scan is disabled in the Hub config (addons.code_scan_enabled).');

            return self::SUCCESS;
        }

        $summary = $cs['summary'] ?? [];
        $total = array_sum($summary);

        $this->line(sprintf(
            'tool=%s   paths=%d   files=%d   duration=%.1fs   findings=%d',
            $cs['tool'] ?? '?',
            count($cs['scanned_paths'] ?? []),
            (int) ($cs['scanned_files'] ?? 0),
            (float) ($cs['duration_seconds'] ?? 0),
            $total,
        ));
        $this->line(sprintf(
            '<fg=red>C=%d</>  <fg=red>H=%d</>  <fg=yellow>M=%d</>  <fg=blue>L=%d</>  <fg=gray>I=%d</>',
            (int) ($summary['critical'] ?? 0),
            (int) ($summary['high'] ?? 0),
            (int) ($summary['medium'] ?? 0),
            (int) ($summary['low'] ?? 0),
            (int) ($summary['info'] ?? 0),
        ));

        if ($this->option('format') === 'json') {
            $this->line(json_encode($cs, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        } else {
            $this->renderFindings($cs['findings'] ?? []);
        }

        if ($out = $this->option('out')) {
            @file_put_contents($out, json_encode($cs, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
            $this->line("📝 Report written to: {$out}");
        }

        if ($this->option('no-send')) {
            $this->warn('--no-send specified; skipping upload to WAF Hub.');

            return self::SUCCESS;
        }

        // Re-use the compliance report envelope so the Hub merges code-scan
        // rows into A.8.25 / A.8.28 / A.8.29 automatically. The rest of the
        // Annex A checks are cheap so we include them; the Hub will dedupe.
        $this->info('📤 Uploading to Hub (embedded in compliance report)…');
        $report = $analyzer->run();
        $report['code_scan'] = $cs;
        $ok = $waf->reportComplianceReport($report);
        if ($ok) {
            $this->info('✅ Report uploaded.');

            return self::SUCCESS;
        }

        Log::warning('code-scan:run upload failed');
        $this->error('❌ Upload failed — see logs.');

        return self::FAILURE;
    }

    /**
     * @param  array<int, array<string, mixed>>  $findings
     */
    private function renderFindings(array $findings): void
    {
        if (empty($findings)) {
            $this->newLine();
            $this->info('🟢 No vulnerabilities detected.');

            return;
        }

        $severityOrder = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];
        usort($findings, fn ($a, $b) => ($severityOrder[$a['severity'] ?? 'info'] ?? 9) <=> ($severityOrder[$b['severity'] ?? 'info'] ?? 9));

        $rows = [];
        foreach (array_slice($findings, 0, 30) as $f) {
            $rows[] = [
                strtoupper((string) ($f['severity'] ?? 'info')),
                (string) ($f['source'] ?? 'sast'),
                (string) ($f['rule'] ?? ''),
                sprintf('%s:%d', basename((string) ($f['file'] ?? '')), (int) ($f['line'] ?? 0)),
                mb_substr((string) ($f['message'] ?? ''), 0, 64),
            ];
        }
        $this->newLine();
        $this->table(['Severity', 'Source', 'Rule', 'Location', 'Message'], $rows);

        if (count($findings) > 30) {
            $this->line(sprintf('… and %d more finding(s) — use --format=json for the full list.', count($findings) - 30));
        }
    }
}
