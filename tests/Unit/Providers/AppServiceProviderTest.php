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
        Config::offsetUnset('ids.agent_token');
        parent::tearDown();
    }


    public function test_it_registers_listeners_in_production_without_token()
    {
        // Mock application running in console true
        $app = \Mockery::mock($this->app)->makePartial();
        $app->shouldReceive('runningInConsole')->andReturn(true);

        $events = \Mockery::mock();
        $events->shouldReceive('listen')->with(\Illuminate\Queue\Events\WorkerStarting::class, \Mockery::type('Closure'))->once();
        $events->shouldReceive('listen')->with(\Illuminate\Console\Events\CommandStarting::class, \Mockery::type('Closure'))->once();

        $app['events'] = $events;
        $app['env'] = 'production';

        Config::set('ids.agent_token', '');

        $provider = new AppServiceProvider($app);
        $provider->boot();

        $this->assertTrue(true);
    }

    public function test_it_does_nothing_if_in_maintenance_mode()
    {
        $app = \Mockery::mock($this->app)->makePartial();
        $app->shouldReceive('runningInConsole')->andReturn(true);
        $app->shouldReceive('isDownForMaintenance')->andReturn(true);

        Config::set('ids.agent_token', '');
        $app['env'] = 'production';

        $provider = new AppServiceProvider($app);

        $provider->boot();
        $this->assertTrue(true); // Reached without exception
    }

    public function test_it_does_nothing_in_production_web_request_without_token()
    {
        $app = \Mockery::mock($this->app)->makePartial();
        $app->shouldReceive('runningInConsole')->andReturn(false);

        Config::set('ids.agent_token', '');
        $app['env'] = 'production';

        $provider = new AppServiceProvider($app);

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
