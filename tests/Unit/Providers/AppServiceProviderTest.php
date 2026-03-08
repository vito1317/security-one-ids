<?php

namespace Tests\Unit\Providers;

use Tests\TestCase;
use App\Providers\AppServiceProvider;
use Illuminate\Support\Facades\Config;

class AppServiceProviderTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        // Ensure clean state
        Config::set('ids.agent_token', 'token');
    }

    protected function tearDown(): void
    {
        Config::set('ids.agent_token', '');
        \Illuminate\Support\Facades\Artisan::call('up');
        parent::tearDown();
    }


    public function test_it_throws_exception_in_production_without_token()
    {
        Config::set('ids.agent_token', '');
        $this->app['env'] = 'production';

        $provider = new AppServiceProvider($this->app);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('AGENT_TOKEN must be set in production environment.');

        $provider->boot();
    }

    public function test_it_does_nothing_if_in_maintenance_mode()
    {
        \Illuminate\Support\Facades\Artisan::call('down');

        Config::set('ids.agent_token', '');
        $this->app['env'] = 'production';

        $provider = new AppServiceProvider($this->app);

        $provider->boot();
        $this->assertTrue(true); // Reached without exception
    }

    public function test_it_does_nothing_in_production_web_request_without_token()
    {
        $appMock = \Mockery::mock($this->app)->makePartial();
        $appMock->shouldReceive('runningInConsole')->andReturn(false);

        Config::set('ids.agent_token', '');
        $appMock['env'] = 'production';

        $provider = new AppServiceProvider($appMock);

        $provider->boot();
        $this->assertTrue(true); // Reached without exception
    }

    public function test_it_does_nothing_if_token_is_set_in_production()
    {
        Config::set('ids.agent_token', 'valid-token');
        $this->app['env'] = 'production';

        $provider = new AppServiceProvider($this->app);

        $provider->boot();
        $this->assertTrue(true); // Reached without exception
    }

    public function test_it_does_nothing_if_not_production()
    {
        Config::set('ids.agent_token', '');
        $this->app['env'] = 'local';

        $provider = new AppServiceProvider($this->app);

        $provider->boot();
        $this->assertTrue(true); // Reached without exception
    }
}
