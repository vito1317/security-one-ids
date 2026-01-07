<?php

namespace App\Console\Commands;

use App\Services\NotificationService;
use Illuminate\Console\Command;

class TestNotifications extends Command
{
    protected $signature = 'ids:test-notifications';
    protected $description = 'Test all configured notification channels';

    public function handle(): int
    {
        $this->info('Testing notification channels...');
        $this->newLine();

        $notificationService = app(NotificationService::class);
        $results = $notificationService->sendTestNotification();

        if (empty($results)) {
            $this->warn('No notification channels are enabled.');
            $this->info('Enable channels in .env:');
            $this->line('  IDS_ALERT_EMAIL_ENABLED=true');
            $this->line('  IDS_ALERT_WEBHOOK_ENABLED=true');
            $this->line('  IDS_ALERT_SLACK_ENABLED=true');
            $this->line('  IDS_ALERT_DISCORD_ENABLED=true');
            return 0;
        }

        foreach ($results as $channel => $status) {
            if (str_contains($status, 'failed')) {
                $this->error("✗ {$channel}: {$status}");
            } else {
                $this->info("✓ {$channel}: {$status}");
            }
        }

        $this->newLine();
        $this->info('Test notifications completed.');

        return 0;
    }
}
