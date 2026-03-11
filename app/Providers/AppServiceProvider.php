<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Only enforce token check during background processes that are explicitly critical.
        // E.g., block queue worker or schedule worker if misconfigured.
        if ($this->app->environment('production') && $this->app->runningInConsole() && trim((string) config('ids.agent_token', '')) === '') {
            if (!$this->app->isDownForMaintenance()) {
                $criticalCommands = [
                    'queue:work',
                    'schedule:run',
                    'schedule:work',
                    'waf:heartbeat',
                    'waf:sync',
                    'desktop:scan',
                ];

                foreach ($criticalCommands as $command) {
                    if ($this->app->runningConsoleCommand($command)) {
                        throw new \RuntimeException('AGENT_TOKEN must be set in production environment for background processes.');
                    }
                }
            }
        }
    }
}
