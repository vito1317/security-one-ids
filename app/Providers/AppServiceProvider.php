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
        if (app()->environment('production') && trim((string) config('ids.agent_token', '')) === '') {
            // Only register CLI event listeners if we are running in the console
            if ($this->app->runningInConsole()) {
                // Log a warning universally for background CLI tasks rather than crashing them
                $this->app['events']->listen(\Illuminate\Queue\Events\WorkerStarting::class, function (\Illuminate\Queue\Events\WorkerStarting $event) {
                    \Illuminate\Support\Facades\Log::warning('AGENT_TOKEN is missing in production. This may cause background WAF/IDS jobs to fail.');
                });

                // Catch custom background IDS commands before they execute and log explicitly
                $this->app['events']->listen(\Illuminate\Console\Events\CommandStarting::class, function (\Illuminate\Console\Events\CommandStarting $event) {
                    if ($event->command && str_starts_with($event->command, 'ids:')) {
                        \Illuminate\Support\Facades\Log::error("Cannot execute {$event->command}: AGENT_TOKEN must be set in production environment.");
                        // Exit cleanly to prevent the command from continuing without a token,
                        // without throwing an unhandled exception that dumps a stack trace.
                        exit(1);
                    }
                });
            }
        }
    }
}
