<?php declare(strict_types=1);

namespace Net\DNS2\Tests;

use Net\DNS2\Resolver;
use Net\DNS2\Cache\Cache;
use Net\DNS2\Cache\File;
use Net\DNS2\Exception;
use PHPUnit\Framework\TestCase;

class CacheTest extends TestCase
{
    private string $cacheFile;

    protected function setUp(): void
    {
        $this->cacheFile = tempnam(sys_get_temp_dir(), 'dns2_');
    }

    protected function tearDown(): void
    {
        @unlink($this->cacheFile);
    }

    public function testFileCacheOpen(): void
    {
        $cache = new File();
        $cache->open($this->cacheFile, 50000, 'serialize');
        $this->assertFalse($cache->has('nonexistent'));
    }

    public function testCacheHasAndGet(): void
    {
        $cache = new Cache();
        $this->assertFalse($cache->has('key'));
        $this->assertFalse($cache->get('key'));
    }

    public function testCacheTypeFile(): void
    {
        $r = new Resolver([
            'nameservers' => ['8.8.8.8'],
            'cache_type'  => 'file',
            'cache_file'  => $this->cacheFile,
        ]);
        $result = $r->query('google.com', 'A');
        $this->assertGreaterThan(0, count($result->answer));
    }

    public function testInvalidCacheType(): void
    {
        $this->expectException(Exception::class);
        new Resolver(['nameservers' => ['8.8.8.8'], 'cache_type' => 'invalid']);
    }
}
