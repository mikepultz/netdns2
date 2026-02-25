<?php declare(strict_types=1);

namespace Net\DNS2\Tests;

use Net\DNS2\Lookups;
use PHPUnit\Framework\TestCase;

class LookupsTest extends TestCase
{
    public function testRRTypes(): void
    {
        $this->assertSame(1, Lookups::$rr_types_by_name['A']);
        $this->assertSame(15, Lookups::$rr_types_by_name['MX']);
        $this->assertSame('A', Lookups::$rr_types_by_id[1]);
    }

    public function testClasses(): void
    {
        $this->assertSame(1, Lookups::$classes_by_name['IN']);
        $this->assertSame('IN', Lookups::$classes_by_id[1]);
    }

    public function testTypedConstants(): void
    {
        $this->assertSame(12, Lookups::DNS_HEADER_SIZE);
        $this->assertSame(512, Lookups::DNS_MAX_UDP_SIZE);
        $this->assertSame(0, Lookups::QR_QUERY);
        $this->assertSame(1, Lookups::QR_RESPONSE);
    }

    public function testIdToClassMapping(): void
    {
        $this->assertSame(\Net\DNS2\RR\A::class, Lookups::$rr_types_id_to_class[1]);
        $this->assertSame(\Net\DNS2\RR\MX::class, Lookups::$rr_types_id_to_class[15]);
    }

    public function testReverseLookups(): void
    {
        $this->assertNotEmpty(Lookups::$rr_types_by_id);
        $this->assertNotEmpty(Lookups::$classes_by_id);
        $this->assertNotEmpty(Lookups::$rr_types_class_to_id);
    }

    public function testResultCodeMessages(): void
    {
        $this->assertStringContainsString('successfully', Lookups::$result_code_messages[0]);
    }

    public function testAlgorithms(): void
    {
        $this->assertSame('RSASHA256', Lookups::$algorithm_id_to_name[8]);
        $this->assertSame(8, Lookups::$algorithm_name_to_id['RSASHA256']);
    }
}
