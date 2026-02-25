<?php declare(strict_types=1);

require_once 'Net/DNS2.php';

use PHPUnit\Framework\TestCase;

class ResolverTest extends TestCase
{
    private function makeResolver(): Net_DNS2_Resolver
    {
        return new Net_DNS2_Resolver([
            'nameservers' => ['8.8.8.8', '8.8.4.4'],
        ]);
    }

    public function testResolverCreation(): void
    {
        $r = $this->makeResolver();
        $this->assertInstanceOf(Net_DNS2_Resolver::class, $r);
        $this->assertInstanceOf(Net_DNS2::class, $r);
    }

    public function testQueryA(): void
    {
        $r = $this->makeResolver();
        $result = $r->query('google.com', 'A');

        $this->assertInstanceOf(Net_DNS2_Packet_Response::class, $result);
        $this->assertSame(Net_DNS2_Lookups::QR_RESPONSE, $result->header->qr);
        $this->assertCount(1, $result->question);
        $this->assertGreaterThan(0, count($result->answer));
        $this->assertInstanceOf(Net_DNS2_RR_A::class, $result->answer[0]);
    }

    public function testQueryMX(): void
    {
        $r = $this->makeResolver();
        $result = $r->query('google.com', 'MX');

        $this->assertSame(Net_DNS2_Lookups::QR_RESPONSE, $result->header->qr);
        $this->assertGreaterThan(0, count($result->answer));
        $this->assertInstanceOf(Net_DNS2_RR_MX::class, $result->answer[0]);
    }

    public function testQuerySOA(): void
    {
        $r = $this->makeResolver();
        $result = $r->query('google.com', 'SOA');

        $this->assertSame(0, $result->header->rcode);
        $this->assertGreaterThan(0, count($result->answer));
    }

    public function testQueryNS(): void
    {
        $r = $this->makeResolver();
        $result = $r->query('google.com', 'NS');

        $this->assertGreaterThan(0, count($result->answer));
        $this->assertInstanceOf(Net_DNS2_RR_NS::class, $result->answer[0]);
    }

    public function testDNSSEC(): void
    {
        $r = $this->makeResolver();
        $r->dnssec = true;

        $result = $r->query('org', 'SOA', 'IN');

        $this->assertSame(1, $result->header->ad);
        $this->assertInstanceOf(Net_DNS2_RR_OPT::class, $result->additional[0]);
        $this->assertSame(1, $result->additional[0]->do);
    }

    public function testNoServersThrows(): void
    {
        $this->expectException(Net_DNS2_Exception::class);
        new Net_DNS2_Resolver(['nameservers' => []]);
    }

    public function testCacheableTypes(): void
    {
        $r = $this->makeResolver();

        $this->assertTrue($r->cacheable('A'));
        $this->assertTrue($r->cacheable('MX'));
        $this->assertFalse($r->cacheable('AXFR'));
        $this->assertFalse($r->cacheable('OPT'));
    }

    public function testIPValidation(): void
    {
        $this->assertTrue(Net_DNS2::isIPv4('192.168.1.1'));
        $this->assertTrue(Net_DNS2::isIPv4('8.8.8.8'));
        $this->assertFalse(Net_DNS2::isIPv4('invalid'));
        $this->assertFalse(Net_DNS2::isIPv4('::1'));

        $this->assertTrue(Net_DNS2::isIPv6('::1'));
        $this->assertTrue(Net_DNS2::isIPv6('2001:db8::1'));
        $this->assertFalse(Net_DNS2::isIPv6('192.168.1.1'));
        $this->assertFalse(Net_DNS2::isIPv6('invalid'));
    }

    public function testExpandIPv6(): void
    {
        $expanded = Net_DNS2::expandIPv6('::1');
        $this->assertSame('0000:0000:0000:0000:0000:0000:0000:0001', $expanded);
    }

    public function testExpandUint32(): void
    {
        $this->assertSame(42, Net_DNS2::expandUint32(42));
        $this->assertSame(0, Net_DNS2::expandUint32(0));
    }
}
