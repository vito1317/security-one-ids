<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

class ListenRuleUpdates extends Command
{
    protected $signature = 'ids:listen-rules {--agent-id=}';
    protected $description = 'Listen for rule updates via SSE';

    public function handle(): int
    {
        $agentId = $this->option('agent-id') ?? env('IDS_AGENT_ID');
        
        if (!$agentId) {
            $this->error('Agent ID not specified');
            return 1;
        }

        $wafUrl = env('WAF_HUB_URL');
        $token = env('WAF_AGENT_TOKEN');

        if (!$wafUrl || !$token) {
            $this->error('WAF Hub URL or token not configured');
            return 1;
        }

        $this->info("Connecting to rule update stream for Agent #{$agentId}...");

        // Use curl for SSE connection
        $url = "{$wafUrl}/ids/rules/stream?agent_id={$agentId}";
        
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, false);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Accept: text/event-stream',
            'Cache-Control: no-cache',
        ]);
        curl_setopt($ch, CURLOPT_WRITEFUNCTION, function ($ch, $data) {
            $this->handleSseData($data);
            return strlen($data);
        });

        curl_exec($ch);
        
        if (curl_errno($ch)) {
            $this->error('Connection error: ' . curl_error($ch));
            curl_close($ch);
            return 1;
        }

        curl_close($ch);
        return 0;
    }

    private function handleSseData(string $data): void
    {
        if (empty(trim($data))) {
            return;
        }

        // Parse SSE format
        if (preg_match('/^event: (.+)$/m', $data, $eventMatch)) {
            $event = trim($eventMatch[1]);
            
            if (preg_match('/^data: (.+)$/m', $data, $dataMatch)) {
                $eventData = json_decode(trim($dataMatch[1]), true);
                
                match ($event) {
                    'connected' => $this->info('✓ Connected to stream'),
                    'heartbeat' => $this->line('.'),
                    'rule_update' => $this->handleRuleUpdate($eventData),
                    default => null,
                };
            }
        }
    }

    private function handleRuleUpdate(array $data): void
    {
        $this->info('📥 Received rule update');
        
        $globalRules = $data['global_rules'] ?? [];
        $agentRules = $data['agent_rules'] ?? [];
        
        $this->line("Global rules: " . count($globalRules));
        $this->line("Agent rules: " . count($agentRules));

        // Save rules to local file/cache
        $rulesPath = storage_path('app/ids_rules.json');
        file_put_contents($rulesPath, json_encode([
            'global_rules' => $globalRules,
            'agent_rules' => $agentRules,
            'updated_at' => $data['timestamp'] ?? now()->toIso8601String(),
        ], JSON_PRETTY_PRINT));

        $this->info("✓ Rules saved to {$rulesPath}");
        
        Log::info('Rules updated via SSE', [
            'global_count' => count($globalRules),
            'agent_count' => count($agentRules),
        ]);
    }
}
