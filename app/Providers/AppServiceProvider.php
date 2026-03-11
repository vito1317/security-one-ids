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
        if ($this->app->environment('production') && $this->app->runningInConsole() && trim(config('ids.agent_token', '')) === '') {
            if (!$this->app->isDownForMaintenance()) {
                $command = $_SERVER['argv'][1] ?? '';
                if (in_array($command, ['queue:work', 'schedule:run', 'schedule:work'], true)) {
                    throw new \RuntimeException('AGENT_TOKEN must be set in production environment for background processes.');
                }
            }
        }
    }
}
