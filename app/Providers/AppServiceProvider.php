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
        if ($this->app->environment('production') && trim(config('ids.agent_token', '')) === '') {
            if (!$this->app->isDownForMaintenance()) {
                throw new \RuntimeException('AGENT_TOKEN must be set in production environment.');
            }
        }
    }
}
