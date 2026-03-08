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
        $safeCommands = [
            'package:discover',
            'vendor:publish',
            'key:generate',
            'optimize',
            'optimize:clear',
            'config:cache',
            'config:clear',
            'route:cache',
            'route:clear',
            'view:cache',
            'view:clear',
            'event:cache',
            'event:clear',
            'migrate',
            'migrate:status',
            'about',
            'help',
            'list',
            'env',
            'clear-compiled',
        ];

        if ($this->app->environment('production') && $this->app->runningInConsole() && trim(config('ids.agent_token', '')) === '') {
            if (!$this->app->isDownForMaintenance() && !$this->app->runningConsoleCommand(...$safeCommands)) {
                throw new \RuntimeException('AGENT_TOKEN must be set in production environment.');
            }
        }
    }
}
