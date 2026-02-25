<?php declare(strict_types=1);

namespace Net\DNS2\Tests;

use Net\DNS2\DNS2;
use Net\DNS2\Resolver;
use Net\DNS2\Lookups;
use Net\DNS2\RR\A;
use Net\DNS2\RR\MX;
use Net\DNS2\RR\NS as RR_NS;
use Net\DNS2\RR\OPT;
use Net\DNS2\Packet\Response;
use Net\DNS2\Exception;
use PHPUnit\Framework\TestCase;

class ResolverTest extends TestCase
{
    private function makeResolver(): Resolver
    {
        return new Resolver(['nameservers' => ['8.8.8.8', '8.8.4.4']]);
    }

    public function testCreation(): void
    {
        $r = $this->makeResolver();
        $this->assertInstanceOf(Resolver::class, $r);
        $this->assertInstanceOf(DNS2::class, $r);
    }

    public function testQueryA(): void
    {
        $result = $this->makeResolver()->query('google.com', 'A');
        $this->assertInstanceOf(Response::class, $result);
        $this->assertSame(Lookups::QR_RESPONSE, $result->header->qr);
        $this->assertGreaterThan(0, count($result->answer));
        $this->assertInstanceOf(A::class, $result->answer[0]);
    }

    public function testQueryMX(): void
    {
        $result = $this->makeResolver()->query('google.com', 'MX');
        $this->assertGreaterThan(0, count($result->answer));
        $this->assertInstanceOf(MX::class, $result->answer[0]);
    }

    public function testQueryNS(): void
    {
        $result = $this->makeResolver()->query('google.com', 'NS');
        $this->assertGreaterThan(0, count($result->answer));
        $this->assertInstanceOf(RR_NS::class, $result->answer[0]);
    }

    public function testDNSSEC(): void
    {
        $r = $this->makeResolver();
        $r->dnssec = true;
        $result = $r->query('org', 'SOA', 'IN');

        $this->assertSame(1, $result->header->ad);
        $this->assertInstanceOf(OPT::class, $result->additional[0]);
        $this->assertSame(1, $result->additional[0]->do);
    }

    public function testNoServersThrows(): void
    {
        $this->expectException(Exception::class);
        new Resolver(['nameservers' => []]);
    }

    public function testCacheable(): void
    {
        $r = $this->makeResolver();
        $this->assertTrue($r->cacheable('A'));
        $this->assertFalse($r->cacheable('AXFR'));
        $this->assertFalse($r->cacheable('OPT'));
    }

    public function testIPValidation(): void
    {
        $this->assertTrue(DNS2::isIPv4('192.168.1.1'));
        $this->assertFalse(DNS2::isIPv4('::1'));
        $this->assertTrue(DNS2::isIPv6('::1'));
        $this->assertFalse(DNS2::isIPv6('192.168.1.1'));
    }

    public function testExpandIPv6(): void
    {
        $this->assertSame('0000:0000:0000:0000:0000:0000:0000:0001', DNS2::expandIPv6('::1'));
    }
}
