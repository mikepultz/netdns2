<?php declare(strict_types=1);

namespace Net\DNS2\Tests;

use Net\DNS2\Lookups;
use Net\DNS2\Packet\Packet;
use Net\DNS2\Packet\Request;
use Net\DNS2\Packet\Response;
use Net\DNS2\RR\RR;
use Net\DNS2\Exception;
use PHPUnit\Framework\TestCase;

class PacketTest extends TestCase
{
    public function testRequestCreation(): void
    {
        $req = new Request('example.com', 'A', 'IN');
        $this->assertCount(1, $req->question);
        $this->assertSame('example.com', $req->question[0]->qname);
        $this->assertSame('A', $req->question[0]->qtype);
    }

    public function testPTRIPv4(): void
    {
        $req = new Request('192.168.1.1', 'PTR', 'IN');
        $this->assertSame('1.1.168.192.in-addr.arpa', $req->question[0]->qname);
    }

    public function testEmptyName(): void
    {
        $this->expectException(Exception::class);
        new Request('', 'A', 'IN');
    }

    public function testInvalidType(): void
    {
        $this->expectException(Exception::class);
        new Request('example.com', 'INVALID', 'IN');
    }

    public function testWildcard(): void
    {
        $req = new Request('example.com', '*', 'IN');
        $this->assertSame('ANY', $req->question[0]->qtype);
    }

    public function testRoundTrip(): void
    {
        $req = new Request('test.example.com', 'MX', 'IN');
        $data = $req->get();
        $resp = new Response($data, strlen($data));

        $this->assertSame($req->header->id, $resp->header->id);
        $this->assertSame('test.example.com', $resp->question[0]->qname);
        $this->assertSame('MX', $resp->question[0]->qtype);
    }

    public function testReset(): void
    {
        $req = new Request('example.com', 'A', 'IN');
        $req->answer[] = RR::fromString('example.com A 1.2.3.4');
        $req->reset();
        $this->assertCount(0, $req->answer);
    }

    public function testCompression(): void
    {
        $p = new Request('example.com', 'A', 'IN');
        $offset = 0;
        $comp1 = $p->compress('www.example.com', $offset);
        $comp2 = $p->compress('mail.example.com', $offset);
        $this->assertNotEmpty($comp1);
        $this->assertNotEmpty($comp2);
    }

    public function testStaticPack(): void
    {
        $packed = Packet::pack('example.com');
        $this->assertStringEndsWith("\0", $packed);
    }
}
