<?php

namespace Tests\Unit\Providers;

use Tests\TestCase;
use App\Providers\AppServiceProvider;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\App;

class AppServiceProviderTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Ensure clean state
        Config::set('ids.agent_token', 'token');
    }

    public function test_it_throws_exception_in_production_without_token_in_web_request()
    {
        // Set up the environment
        App::detectEnvironment(function () { return 'production'; });
        Config::set('ids.agent_token', '');

        // We need to mock runningInConsole() to return false to simulate a web request
        // since PHPUnit runs in the console by default.
        // The most reliable way is to mock the Application instance for this specific call.

        $appMock = \Mockery::mock($this->app)->makePartial();
        $appMock->shouldReceive('runningInConsole')->andReturn(false);
        $appMock->shouldReceive('environment')->with('production')->andReturn(true);

        // Temporarily replace the app instance
        $originalApp = app();
        \Illuminate\Support\Facades\Facade::setFacadeApplication($appMock);
        // Replace app() helper usage if necessary, but actually app() returns Facade::getFacadeApplication() usually
        // Wait, app() helper returns Container::getInstance().
        \Illuminate\Container\Container::setInstance($appMock);

        $provider = new AppServiceProvider($appMock);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('AGENT_TOKEN must be set in production environment.');

        try {
            $provider->boot();
        } finally {
            // Restore original app instance
            \Illuminate\Container\Container::setInstance($originalApp);
            \Illuminate\Support\Facades\Facade::setFacadeApplication($originalApp);
        }
    }

    public function test_it_logs_warning_in_production_without_token_in_console()
    {
        // Set up the environment
        App::detectEnvironment(function () { return 'production'; });
        Config::set('ids.agent_token', '');

        // It is already running in console (PHPUnit)
        $appMock = \Mockery::mock($this->app)->makePartial();
        $appMock->shouldReceive('runningInConsole')->andReturn(true);
        $appMock->shouldReceive('environment')->with('production')->andReturn(true);

        $originalApp = app();
        \Illuminate\Container\Container::setInstance($appMock);
        \Illuminate\Support\Facades\Facade::setFacadeApplication($appMock);

        Log::shouldReceive('warning')
            ->once()
            ->with('AGENT_TOKEN is empty in production environment during console command. This may lead to an insecure configuration cache.');

        $provider = new AppServiceProvider($appMock);

        try {
            $provider->boot();
        } finally {
            \Illuminate\Container\Container::setInstance($originalApp);
            \Illuminate\Support\Facades\Facade::setFacadeApplication($originalApp);
        }
    }

    public function test_it_does_nothing_if_token_is_set_in_production()
    {
        App::detectEnvironment(function () { return 'production'; });
        Config::set('ids.agent_token', 'valid-token');

        $appMock = \Mockery::mock($this->app)->makePartial();
        $appMock->shouldReceive('environment')->with('production')->andReturn(true);

        $originalApp = app();
        \Illuminate\Container\Container::setInstance($appMock);
        \Illuminate\Support\Facades\Facade::setFacadeApplication($appMock);

        Log::shouldReceive('warning')->never();

        $provider = new AppServiceProvider($appMock);

        try {
            $provider->boot();
            $this->assertTrue(true); // Reached without exception
        } finally {
            \Illuminate\Container\Container::setInstance($originalApp);
            \Illuminate\Support\Facades\Facade::setFacadeApplication($originalApp);
        }
    }

    public function test_it_does_nothing_if_not_production()
    {
        App::detectEnvironment(function () { return 'local'; });
        Config::set('ids.agent_token', '');

        $appMock = \Mockery::mock($this->app)->makePartial();
        $appMock->shouldReceive('environment')->with('production')->andReturn(false);

        $originalApp = app();
        \Illuminate\Container\Container::setInstance($appMock);
        \Illuminate\Support\Facades\Facade::setFacadeApplication($appMock);

        Log::shouldReceive('warning')->never();

        $provider = new AppServiceProvider($appMock);

        try {
            $provider->boot();
            $this->assertTrue(true); // Reached without exception
        } finally {
            \Illuminate\Container\Container::setInstance($originalApp);
            \Illuminate\Support\Facades\Facade::setFacadeApplication($originalApp);
        }
    }
}
