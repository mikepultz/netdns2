<?php declare(strict_types=1);

require_once 'Net/DNS2.php';

use PHPUnit\Framework\TestCase;

class HeaderTest extends TestCase
{
    public function testDefaultHeaderValues(): void
    {
        $h = new Net_DNS2_Header();

        $this->assertSame(Net_DNS2_Lookups::QR_QUERY, $h->qr);
        $this->assertSame(Net_DNS2_Lookups::OPCODE_QUERY, $h->opcode);
        $this->assertSame(0, $h->aa);
        $this->assertSame(0, $h->tc);
        $this->assertSame(1, $h->rd);
        $this->assertSame(0, $h->ra);
        $this->assertSame(0, $h->z);
        $this->assertSame(0, $h->ad);
        $this->assertSame(0, $h->cd);
        $this->assertSame(Net_DNS2_Lookups::RCODE_NOERROR, $h->rcode);
        $this->assertSame(1, $h->qdcount);
        $this->assertSame(0, $h->ancount);
        $this->assertSame(0, $h->nscount);
        $this->assertSame(0, $h->arcount);
    }

    public function testHeaderPackUnpack(): void
    {
        $request = new Net_DNS2_Packet_Request('example.com', 'A', 'IN');
        $data = $request->get();

        $response = new Net_DNS2_Packet_Response($data, strlen($data));

        $this->assertSame($request->header->id, $response->header->id);
        $this->assertSame($request->header->qr, $response->header->qr);
        $this->assertSame($request->header->opcode, $response->header->opcode);
        $this->assertSame($request->header->rd, $response->header->rd);
        $this->assertSame($request->header->qdcount, $response->header->qdcount);
    }

    public function testHeaderToString(): void
    {
        $h = new Net_DNS2_Header();
        $str = (string)$h;

        $this->assertStringContainsString('Header:', $str);
        $this->assertStringContainsString('id', $str);
        $this->assertStringContainsString('qr', $str);
        $this->assertStringContainsString('opcode', $str);
    }

    public function testHeaderTooSmall(): void
    {
        $packet = new Net_DNS2_Packet();
        $packet->rdata = 'short';
        $packet->rdlength = 5;

        $this->expectException(Net_DNS2_Exception::class);
        new Net_DNS2_Header($packet);
    }

    public function testNextPacketId(): void
    {
        $h = new Net_DNS2_Header();
        $id1 = $h->nextPacketId();
        $id2 = $h->nextPacketId();

        $this->assertSame($id1 + 1, $id2);
        $this->assertGreaterThan(0, $id1);
        $this->assertLessThanOrEqual(65535, $id2);
    }
}
