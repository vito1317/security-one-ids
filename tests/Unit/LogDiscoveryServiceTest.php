<?php

namespace Tests\Unit;

use App\Services\LogDiscoveryService;
use Tests\TestCase;
use Illuminate\Support\Facades\Cache;

class LogDiscoveryServiceTest extends TestCase
{
    private LogDiscoveryService $service;

    protected function setUp(): void
    {
        parent::setUp();
        config(['cache.default' => 'array']);
        $this->service = app(LogDiscoveryService::class);
    }

    protected function tearDown(): void
    {
        parent::tearDown();
    }

    public function test_add_custom_path_fails_when_path_not_readable(): void
    {
        $path = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'missing_' . uniqid();

        // ensure the file actually does not exist
        $this->assertFalse(is_readable($path));

        $result = $this->service->addCustomPath($path);

        $this->assertFalse($result);
    }

    public function test_add_custom_path_adds_path_and_caches_when_valid_and_not_in_config(): void
    {
        // Create a temporary readable file
        $tempPath = tempnam(sys_get_temp_dir(), 'test_log');
        $this->assertNotEmpty($tempPath);
        $this->assertFileExists($tempPath);

        try {
            file_put_contents($tempPath, 'test log content');

            \Illuminate\Support\Facades\Config::shouldReceive('get')
                ->with('ids.custom_log_paths', [])
                ->andReturn([]);
            \Illuminate\Support\Facades\Config::makePartial();

            Cache::shouldReceive('forever')
                ->once()
                ->with('ids_custom_log_paths', [$tempPath])
                ->andReturn(true);

            // We must also mock Cache::get() since the service calls getCustomPaths() internally
            Cache::shouldReceive('get')
                ->with('ids_custom_log_paths', [])
                ->andReturn([]);

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);
        } finally {
            if (is_file($tempPath)) {
                unlink($tempPath);
            }
        }
    }

    public function test_add_custom_path_returns_true_without_caching_when_path_already_in_config(): void
    {
        // Create a temporary readable file
        $tempPath = tempnam(sys_get_temp_dir(), 'test_log');
        $this->assertNotEmpty($tempPath);
        $this->assertFileExists($tempPath);

        try {
            file_put_contents($tempPath, 'test log content');

            \Illuminate\Support\Facades\Config::shouldReceive('get')
                ->with('ids.custom_log_paths', [])
                ->andReturn([$tempPath]);
            \Illuminate\Support\Facades\Config::makePartial();

            Cache::shouldReceive('forever')->never();

            $result = $this->service->addCustomPath($tempPath);

            $this->assertTrue($result);
        } finally {
            if (is_file($tempPath)) {
                unlink($tempPath);
            }
        }
    }
}
