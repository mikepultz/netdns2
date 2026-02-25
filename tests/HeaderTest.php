<?php declare(strict_types=1);

namespace Net\DNS2\Tests;

use Net\DNS2\Header;
use Net\DNS2\Lookups;
use Net\DNS2\Packet\Packet;
use Net\DNS2\Packet\Request;
use Net\DNS2\Packet\Response;
use Net\DNS2\Exception;
use PHPUnit\Framework\TestCase;

class HeaderTest extends TestCase
{
    public function testDefaultValues(): void
    {
        $h = new Header();
        $this->assertSame(Lookups::QR_QUERY, $h->qr);
        $this->assertSame(Lookups::OPCODE_QUERY, $h->opcode);
        $this->assertSame(1, $h->rd);
        $this->assertSame(0, $h->tc);
        $this->assertSame(Lookups::RCODE_NOERROR, $h->rcode);
        $this->assertSame(1, $h->qdcount);
    }

    public function testPackUnpack(): void
    {
        $req = new Request('example.com', 'A', 'IN');
        $data = $req->get();
        $resp = new Response($data, strlen($data));

        $this->assertSame($req->header->id, $resp->header->id);
        $this->assertSame($req->header->opcode, $resp->header->opcode);
    }

    public function testToString(): void
    {
        $h = new Header();
        $this->assertStringContainsString('Header:', (string)$h);
    }

    public function testTooSmall(): void
    {
        $p = new Packet();
        $p->rdata = 'short';
        $p->rdlength = 5;
        $this->expectException(Exception::class);
        new Header($p);
    }

    public function testNextPacketId(): void
    {
        $h = new Header();
        $id1 = $h->nextPacketId();
        $id2 = $h->nextPacketId();
        $this->assertSame($id1 + 1, $id2);
    }
}
