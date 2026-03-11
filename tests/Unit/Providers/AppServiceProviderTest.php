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


    public function test_production_without_agent_token_blocks_all_critical_background_commands(): void
    {
        $commands = [
            'queue:work',
            'schedule:run',
            'schedule:work',
            'waf:heartbeat',
            'waf:sync',
            'desktop:scan',
        ];

        foreach ($commands as $command) {
            $app = \Mockery::mock($this->app)->makePartial();
            $app->shouldReceive('runningInConsole')->andReturn(true);
            $app->shouldReceive('isDownForMaintenance')->andReturn(false);

            // Return true ONLY for the current command being tested, false otherwise
            $app->shouldReceive('runningConsoleCommand')->andReturnUsing(function ($cmd) use ($command) {
                return $cmd === $command;
            });

            Config::set('ids.agent_token', '');
            $app['env'] = 'production';

            $provider = new AppServiceProvider($app);

            try {
                $provider->boot();
                $this->fail("Expected RuntimeException was not thrown for command: {$command}");
            } catch (\RuntimeException $e) {
                $this->assertEquals('AGENT_TOKEN must be set in production environment for background processes.', $e->getMessage());
            }
        }
    }

    public function test_it_does_nothing_if_running_safe_command()
    {
        $app = \Mockery::mock($this->app)->makePartial();
        $app->shouldReceive('runningInConsole')->andReturn(true);
        $app->shouldReceive('isDownForMaintenance')->andReturn(false);
        $app->shouldReceive('runningConsoleCommand')->with('queue:work')->andReturn(false);
        $app->shouldReceive('runningConsoleCommand')->with('schedule:run')->andReturn(false);
        $app->shouldReceive('runningConsoleCommand')->with('schedule:work')->andReturn(false);

        Config::set('ids.agent_token', '');
        $app['env'] = 'production';

        $provider = new AppServiceProvider($app);

        $provider->boot();
        $this->assertTrue(true); // Reached without exception
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
