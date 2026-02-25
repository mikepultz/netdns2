<?php declare(strict_types=1);

require_once 'Net/DNS2.php';

use PHPUnit\Framework\TestCase;

class LookupsTest extends TestCase
{
    public function testRRTypesByNameAndId(): void
    {
        $this->assertSame(1, Net_DNS2_Lookups::$rr_types_by_name['A']);
        $this->assertSame(15, Net_DNS2_Lookups::$rr_types_by_name['MX']);
        $this->assertSame(28, Net_DNS2_Lookups::$rr_types_by_name['AAAA']);
        $this->assertSame(6, Net_DNS2_Lookups::$rr_types_by_name['SOA']);

        $this->assertSame('A', Net_DNS2_Lookups::$rr_types_by_id[1]);
        $this->assertSame('MX', Net_DNS2_Lookups::$rr_types_by_id[15]);
    }

    public function testClassesByNameAndId(): void
    {
        $this->assertSame(1, Net_DNS2_Lookups::$classes_by_name['IN']);
        $this->assertSame(255, Net_DNS2_Lookups::$classes_by_name['ANY']);

        $this->assertSame('IN', Net_DNS2_Lookups::$classes_by_id[1]);
        $this->assertSame('ANY', Net_DNS2_Lookups::$classes_by_id[255]);
    }

    public function testTypedConstants(): void
    {
        $this->assertSame(12, Net_DNS2_Lookups::DNS_HEADER_SIZE);
        $this->assertSame(512, Net_DNS2_Lookups::DNS_MAX_UDP_SIZE);
        $this->assertSame(0, Net_DNS2_Lookups::QR_QUERY);
        $this->assertSame(1, Net_DNS2_Lookups::QR_RESPONSE);
        $this->assertSame(0, Net_DNS2_Lookups::RCODE_NOERROR);
        $this->assertSame(3, Net_DNS2_Lookups::RCODE_NXDOMAIN);
    }

    public function testIdToClassMapping(): void
    {
        $this->assertSame('Net_DNS2_RR_A', Net_DNS2_Lookups::$rr_types_id_to_class[1]);
        $this->assertSame('Net_DNS2_RR_MX', Net_DNS2_Lookups::$rr_types_id_to_class[15]);
        $this->assertSame('Net_DNS2_RR_SOA', Net_DNS2_Lookups::$rr_types_id_to_class[6]);
    }

    public function testReverseLookupsPopulated(): void
    {
        $this->assertNotEmpty(Net_DNS2_Lookups::$rr_types_by_id);
        $this->assertNotEmpty(Net_DNS2_Lookups::$classes_by_id);
        $this->assertNotEmpty(Net_DNS2_Lookups::$rr_types_class_to_id);
        $this->assertNotEmpty(Net_DNS2_Lookups::$algorithm_name_to_id);
        $this->assertNotEmpty(Net_DNS2_Lookups::$digest_name_to_id);
    }

    public function testNextPacketId(): void
    {
        $this->assertIsInt(Net_DNS2_Lookups::$next_packet_id);
        $this->assertGreaterThanOrEqual(0, Net_DNS2_Lookups::$next_packet_id);
        $this->assertLessThanOrEqual(65535, Net_DNS2_Lookups::$next_packet_id);
    }

    public function testResultCodeMessages(): void
    {
        $this->assertArrayHasKey(Net_DNS2_Lookups::RCODE_NOERROR, Net_DNS2_Lookups::$result_code_messages);
        $this->assertArrayHasKey(Net_DNS2_Lookups::RCODE_NXDOMAIN, Net_DNS2_Lookups::$result_code_messages);
        $this->assertStringContainsString('successfully', Net_DNS2_Lookups::$result_code_messages[0]);
    }

    public function testAlgorithmMappings(): void
    {
        $this->assertSame('RSASHA256', Net_DNS2_Lookups::$algorithm_id_to_name[8]);
        $this->assertSame(8, Net_DNS2_Lookups::$algorithm_name_to_id['RSASHA256']);
    }
}
