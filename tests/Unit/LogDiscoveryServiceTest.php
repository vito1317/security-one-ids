<?php

namespace Tests\Unit;

use App\Services\LogDiscoveryService;
use Tests\TestCase;
use Illuminate\Support\Facades\Cache;

class LogDiscoveryServiceTest extends TestCase
{
    private LogDiscoveryService $service;
    private array $tempFiles = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->service = new LogDiscoveryService();
        Cache::flush();
    }

    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $tempFile) {
            if (file_exists($tempFile)) {
                unlink($tempFile);
            }
        }
        parent::tearDown();
    }

    public function test_add_custom_path_uses_new_cache_key(): void
    {
        $tempPath = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'test_log_1_' . uniqid() . '.log';
        file_put_contents($tempPath, "test");
        $this->tempFiles[] = $tempPath;

        $this->assertTrue($this->service->addCustomPath($tempPath));

        $this->assertTrue(Cache::has('ids.custom_log_paths'));
        $this->assertFalse(Cache::has('ids_custom_log_paths'));

        $cachedPaths = Cache::get('ids.custom_log_paths');
        $this->assertContains($tempPath, $cachedPaths);
    }

    public function test_get_custom_paths_migrates_legacy_key(): void
    {
        $legacyPaths = ['/var/log/custom1.log'];
        Cache::forever('ids_custom_log_paths', $legacyPaths);

        $paths = $this->service->getCustomPaths();

        $this->assertContains('/var/log/custom1.log', $paths);
        $this->assertFalse(Cache::has('ids_custom_log_paths'));
        $this->assertTrue(Cache::has('ids.custom_log_paths'));

        $newCachedPaths = Cache::get('ids.custom_log_paths');
        $this->assertContains('/var/log/custom1.log', $newCachedPaths);
    }
}
