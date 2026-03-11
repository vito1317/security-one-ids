<?php

namespace Tests\Unit;

use App\Services\LogDiscoveryService;
use Tests\TestCase;

class LogDiscoveryServiceTest extends TestCase
{
    private array $tempFiles = [];

    protected function setUp(): void
    {
        parent::setUp();
    }

    protected function tearDown(): void
    {
        cache()->forget(LogDiscoveryService::CACHE_KEY_CUSTOM_PATHS);
        config(['ids.custom_log_paths' => []]);

        foreach ($this->tempFiles as $file) {
            if (file_exists($file)) {
                @unlink($file);
            }
        }

        parent::tearDown();
    }

    private function createTempLogFile(): string
    {
        if (!is_writable(sys_get_temp_dir())) {
            $this->markTestSkipped('Temp directory is not writable');
        }

        $tempPath = tempnam(sys_get_temp_dir(), uniqid('test_log_', true));
        if ($tempPath === false) {
            $this->fail('Failed to create temporary file.');
        }

        file_put_contents($tempPath, 'test log content');
        $this->tempFiles[] = $tempPath;

        return $tempPath;
    }

    public function test_add_custom_path_fails_when_path_not_readable(): void
    {
        cache()->forget(LogDiscoveryService::CACHE_KEY_CUSTOM_PATHS);
        config(['ids.custom_log_paths' => []]);
        $service = app(LogDiscoveryService::class);

        $path = '/path/to/non/existent/file.log';

        // ensure the file actually does not exist
        $this->assertFalse(is_readable($path));

        $result = $service->addCustomPath($path);

        $this->assertFalse($result);
        $this->assertFalse(cache()->has('ids.custom_log_paths'));
    }

    public function test_add_custom_path_adds_path_and_caches_when_valid_and_not_in_config(): void
    {
        cache()->forget(LogDiscoveryService::CACHE_KEY_CUSTOM_PATHS);
        config(['ids.custom_log_paths' => []]);
        $service = app(LogDiscoveryService::class);

        $tempPath = $this->createTempLogFile();

        $result = $service->addCustomPath($tempPath);

        $this->assertTrue($result);

        // Verify the actual cache state
        $this->assertTrue(cache()->has(LogDiscoveryService::CACHE_KEY_CUSTOM_PATHS));
        $this->assertEquals([$tempPath], cache()->get(LogDiscoveryService::CACHE_KEY_CUSTOM_PATHS));
    }

    public function test_add_custom_path_caches_path_when_path_already_in_config_but_cache_empty(): void
    {
        cache()->forget(LogDiscoveryService::CACHE_KEY_CUSTOM_PATHS);
        $tempPath = $this->createTempLogFile();

        // Setup config with the path already in it
        config(['ids.custom_log_paths' => [$tempPath]]);
        $service = app(LogDiscoveryService::class);

        $result = $service->addCustomPath($tempPath);

        $this->assertTrue($result);

        // Verify cache is populated to ensure consistency
        $this->assertTrue(cache()->has(LogDiscoveryService::CACHE_KEY_CUSTOM_PATHS));
        $this->assertEquals([$tempPath], cache()->get(LogDiscoveryService::CACHE_KEY_CUSTOM_PATHS));
    }

    public function test_add_custom_path_is_idempotent_when_path_in_both_config_and_cache(): void
    {
        cache()->forget(LogDiscoveryService::CACHE_KEY_CUSTOM_PATHS);
        $tempPath = $this->createTempLogFile();

        // Setup config with the path already in it
        config(['ids.custom_log_paths' => [$tempPath]]);
        $service = app(LogDiscoveryService::class);

        // Also mock the cache to already have it
        cache()->forever(LogDiscoveryService::CACHE_KEY_CUSTOM_PATHS, [$tempPath]);

        // Attempt to add it again
        $result = $service->addCustomPath($tempPath);

        $this->assertTrue($result);

        // Verify it didn't do something unexpected
        $cachedPaths = cache()->get(LogDiscoveryService::CACHE_KEY_CUSTOM_PATHS);
        $this->assertEquals([$tempPath], $cachedPaths);
        $this->assertCount(1, $cachedPaths);
    }
}
