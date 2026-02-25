<?php declare(strict_types=1);

require_once 'Net/DNS2.php';

use PHPUnit\Framework\TestCase;

class CacheTest extends TestCase
{
    private string $cacheFile;

    protected function setUp(): void
    {
        $this->cacheFile = tempnam(sys_get_temp_dir(), 'dns2_cache_');
    }

    protected function tearDown(): void
    {
        if (file_exists($this->cacheFile)) {
            @unlink($this->cacheFile);
        }
    }

    public function testFileCacheOpenAndClose(): void
    {
        $cache = new Net_DNS2_Cache_File();
        $cache->open($this->cacheFile, 50000, 'serialize');

        $this->assertFalse($cache->has('nonexistent'));
        $this->assertFalse($cache->get('nonexistent'));
    }

    public function testCacheHasAndGet(): void
    {
        $cache = new Net_DNS2_Cache();

        $this->assertFalse($cache->has('key'));
        $this->assertFalse($cache->get('key'));
    }

    public function testCacheTypeNone(): void
    {
        $r = new Net_DNS2_Resolver([
            'nameservers' => ['8.8.8.8'],
            'cache_type'  => 'none',
        ]);

        $this->assertInstanceOf(Net_DNS2_Resolver::class, $r);
    }

    public function testCacheTypeFile(): void
    {
        $r = new Net_DNS2_Resolver([
            'nameservers' => ['8.8.8.8'],
            'cache_type'  => 'file',
            'cache_file'  => $this->cacheFile,
        ]);

        $result = $r->query('google.com', 'A');
        $this->assertGreaterThan(0, count($result->answer));
    }

    public function testInvalidCacheType(): void
    {
        $this->expectException(Net_DNS2_Exception::class);
        new Net_DNS2_Resolver([
            'nameservers' => ['8.8.8.8'],
            'cache_type'  => 'invalid',
        ]);
    }
}
