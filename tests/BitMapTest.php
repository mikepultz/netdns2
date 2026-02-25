<?php declare(strict_types=1);

namespace Net\DNS2\Tests;

use Net\DNS2\BitMap;
use PHPUnit\Framework\TestCase;

class BitMapTest extends TestCase
{
    public function testEmptyBitMap(): void
    {
        $this->assertSame([], BitMap::bitMapToArray(''));
    }

    public function testEmptyArray(): void
    {
        $this->assertSame('', BitMap::arrayToBitMap([]));
    }

    public function testRoundTrip(): void
    {
        $types = ['A', 'MX', 'RRSIG', 'NSEC'];
        $bitmap = BitMap::arrayToBitMap($types);
        $result = BitMap::bitMapToArray($bitmap);
        foreach ($types as $t) {
            $this->assertContains($t, $result);
        }
    }

    public function testBigBaseConvert(): void
    {
        $this->assertSame('CC', BitMap::bigBaseConvert('11001100'));
    }
}
