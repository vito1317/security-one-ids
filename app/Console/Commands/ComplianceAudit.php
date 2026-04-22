<?php

namespace App\Console\Commands;

use App\Services\ComplianceAnalyzer;
use App\Services\WafSyncService;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class ComplianceAudit extends Command
{
    protected $signature = 'compliance:audit
        {--format=table : Output format (table|json)}
        {--no-send : Do not POST the result to the WAF Hub}
        {--out= : Optional path to write the full JSON report}';

    protected $description = 'Run ISO 27001 Annex A compliance checks on this host and report to the WAF Hub';

    public function handle(ComplianceAnalyzer $analyzer, WafSyncService $waf): int
    {
        $this->info('🔎 Running ISO 27001 compliance checks…');
        $report = $analyzer->run();

        // Persist to storage/app for local reference and dashboard-less debugging.
        $defaultPath = storage_path('app/compliance_report.json');
        $outPath = $this->option('out') ?: $defaultPath;
        @file_put_contents($outPath, json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        $this->line("📝 Local report written to: {$outPath}");

        if ($this->option('format') === 'json') {
            $this->line(json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        } else {
            $this->renderTable($report);
        }

        if ($this->option('no-send')) {
            $this->warn('⚠️  --no-send specified; skipping upload to WAF Hub.');
            return self::SUCCESS;
        }

        $ok = $waf->reportComplianceReport($report);
        if ($ok) {
            $this->info('✅ Compliance report uploaded to WAF Hub.');
            return self::SUCCESS;
        }

        $this->error('❌ Failed to upload compliance report — see logs.');
        Log::warning('compliance:audit upload failed', ['score' => $report['overall_score'] ?? null]);
        return self::FAILURE;
    }

    private function renderTable(array $report): void
    {
        $this->newLine();
        $this->line(sprintf(
            '<options=bold>Framework:</> %s   <options=bold>Host:</> %s   <options=bold>Score:</> %s%%',
            $report['framework'],
            $report['hostname'] ?? 'n/a',
            $report['overall_score'],
        ));
        $this->line(sprintf(
            '<fg=green>Pass=%d</>  <fg=red>Fail=%d</>  <fg=yellow>Warn=%d</>  <fg=gray>N/A=%d</>  (%d applicable of %d total)',
            $report['passed_checks'],
            $report['failed_checks'],
            $report['warning_checks'],
            $report['not_applicable_checks'],
            $report['applicable_checks'],
            $report['total_checks'],
        ));
        $this->newLine();

        $rows = [];
        foreach ($report['checks'] as $c) {
            $rows[] = [
                $c['control_id'],
                $c['control_name'],
                $this->colorStatus($c['status']),
                strtoupper($c['severity']),
                $this->truncate($c['description'], 60),
            ];
        }
        $this->table(['Control', 'Name', 'Status', 'Severity', 'Description'], $rows);
    }

    private function colorStatus(string $status): string
    {
        return match ($status) {
            ComplianceAnalyzer::STATUS_PASS => '<fg=green>PASS</>',
            ComplianceAnalyzer::STATUS_FAIL => '<fg=red>FAIL</>',
            ComplianceAnalyzer::STATUS_WARNING => '<fg=yellow>WARN</>',
            default => '<fg=gray>N/A</>',
        };
    }

    private function truncate(string $s, int $n): string
    {
        return mb_strlen($s) > $n ? mb_substr($s, 0, $n - 1) . '…' : $s;
    }
}
