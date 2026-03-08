<?php

namespace Tests\Unit;

use App\Services\LogDiscoveryService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Tests\TestCase;

class LogDiscoveryServiceTest extends TestCase
{
    /** @var array<string> */
    private array $tempFiles = [];

    protected function tearDown(): void
    {
        foreach ($this->tempFiles as $tempFile) {
            if (file_exists($tempFile)) {
                @unlink($tempFile);
            }
        }

        parent::tearDown();
    }

    public function testAddCustomPath(): void
    {
        $service = new LogDiscoveryService();
        $tempPath = tempnam(sys_get_temp_dir(), 'test_log_');

        $this->assertIsString($tempPath);
        $this->assertNotEmpty($tempPath);

        // Ensure file exists and is writable to pass initial check
        $this->assertTrue(file_exists($tempPath));
        $this->assertTrue(is_writable($tempPath));

        $this->tempFiles[] = $tempPath;

        // Mock Cache facade explicitly to verify correct interactions
        Cache::shouldReceive('get')
            ->with('ids_custom_log_paths', [])
            ->once()
            ->andReturn([]);
        Cache::shouldReceive('get')
            ->with('ids.custom_log_paths', [])
            ->once()
            ->andReturn([]);

        Cache::shouldReceive('has')
            ->with('ids_custom_log_paths')
            ->once()
            ->andReturn(false);
        Cache::shouldReceive('has')
            ->with('ids::custom_log_paths')
            ->once()
            ->andReturn(false);

        Cache::shouldReceive('forever')
            ->with('ids.custom_log_paths', [$tempPath])
            ->once();

        $result = $service->addCustomPath($tempPath);

        $this->assertTrue($result);
    }

    public function testAddCustomPathAlreadyCached(): void
    {
        $service = new LogDiscoveryService();
        $tempPath = tempnam(sys_get_temp_dir(), 'test_log_');

        $this->assertIsString($tempPath);
        $this->assertNotEmpty($tempPath);

        $this->assertTrue(file_exists($tempPath));
        $this->assertTrue(is_writable($tempPath));

        $this->tempFiles[] = $tempPath;

        // Mock Cache facade explicitly
        Cache::shouldReceive('get')
            ->with('ids_custom_log_paths', [])
            ->once()
            ->andReturn([]);
        Cache::shouldReceive('get')
            ->with('ids.custom_log_paths', [])
            ->once()
            ->andReturn([$tempPath]);

        Cache::shouldReceive('has')
            ->with('ids_custom_log_paths')
            ->once()
            ->andReturn(false);
        Cache::shouldReceive('has')
            ->with('ids::custom_log_paths')
            ->once()
            ->andReturn(false);

        // Forever should NOT be called since it is already in the array
        Cache::shouldReceive('forever')->never();

        $result = $service->addCustomPath($tempPath);

        $this->assertTrue($result);
    }
}
