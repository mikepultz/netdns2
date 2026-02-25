<?php declare(strict_types=1);

require_once 'Net/DNS2.php';

use PHPUnit\Framework\TestCase;

class BitMapTest extends TestCase
{
    public function testEmptyBitMap(): void
    {
        $this->assertSame([], Net_DNS2_BitMap::bitMapToArray(''));
    }

    public function testEmptyArrayToBitMap(): void
    {
        $this->assertSame('', Net_DNS2_BitMap::arrayToBitMap([]));
    }

    public function testBitMapRoundTrip(): void
    {
        $types = ['A', 'MX', 'RRSIG', 'NSEC'];

        $bitmap = Net_DNS2_BitMap::arrayToBitMap($types);
        $this->assertNotEmpty($bitmap);

        $result = Net_DNS2_BitMap::bitMapToArray($bitmap);

        foreach ($types as $type) {
            $this->assertContains($type, $result, "Missing type: {$type}");
        }
    }

    public function testBigBaseConvert(): void
    {
        $result = Net_DNS2_BitMap::bigBaseConvert('11001100');
        $this->assertSame('CC', $result);

        $result = Net_DNS2_BitMap::bigBaseConvert('10101010');
        $this->assertSame('AA', $result);
    }
}
