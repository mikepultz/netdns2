<?php declare(strict_types=1);

require_once 'Net/DNS2.php';

use PHPUnit\Framework\TestCase;

class PacketTest extends TestCase
{
    public function testRequestPacketCreation(): void
    {
        $request = new Net_DNS2_Packet_Request('example.com', 'A', 'IN');

        $this->assertInstanceOf(Net_DNS2_Header::class, $request->header);
        $this->assertCount(1, $request->question);
        $this->assertSame('example.com', $request->question[0]->qname);
        $this->assertSame('A', $request->question[0]->qtype);
        $this->assertSame('IN', $request->question[0]->qclass);
    }

    public function testRequestPTRIPv4(): void
    {
        $request = new Net_DNS2_Packet_Request('192.168.1.1', 'PTR', 'IN');

        $this->assertSame('1.1.168.192.in-addr.arpa', $request->question[0]->qname);
    }

    public function testRequestEmptyName(): void
    {
        $this->expectException(Net_DNS2_Exception::class);
        new Net_DNS2_Packet_Request('', 'A', 'IN');
    }

    public function testRequestInvalidType(): void
    {
        $this->expectException(Net_DNS2_Exception::class);
        new Net_DNS2_Packet_Request('example.com', 'INVALID', 'IN');
    }

    public function testRequestWildcard(): void
    {
        $request = new Net_DNS2_Packet_Request('example.com', '*', 'IN');
        $this->assertSame('ANY', $request->question[0]->qtype);
    }

    public function testRequestRootDomain(): void
    {
        $request = new Net_DNS2_Packet_Request('.', 'NS', 'IN');
        $this->assertSame('.', $request->question[0]->qname);
    }

    public function testRoundTripPacket(): void
    {
        $request = new Net_DNS2_Packet_Request('test.example.com', 'MX', 'IN');
        $data = $request->get();

        $this->assertGreaterThan(Net_DNS2_Lookups::DNS_HEADER_SIZE, strlen($data));

        $response = new Net_DNS2_Packet_Response($data, strlen($data));

        $this->assertSame($request->header->id, $response->header->id);
        $this->assertCount(1, $response->question);
        $this->assertSame('test.example.com', $response->question[0]->qname);
        $this->assertSame('MX', $response->question[0]->qtype);
    }

    public function testPacketCopy(): void
    {
        $p1 = new Net_DNS2_Packet_Request('example.com', 'A', 'IN');
        $p2 = new Net_DNS2_Packet();

        $p2->copy($p1);

        $this->assertSame($p1->header, $p2->header);
        $this->assertSame($p1->question, $p2->question);
    }

    public function testPacketReset(): void
    {
        $request = new Net_DNS2_Packet_Request('example.com', 'A', 'IN');
        $old_id = $request->header->id;

        $request->answer[] = Net_DNS2_RR::fromString('example.com A 1.2.3.4');
        $request->reset();

        $this->assertNotSame($old_id, $request->header->id);
        $this->assertCount(0, $request->answer);
        $this->assertSame(0, $request->offset);
    }

    public function testPacketToString(): void
    {
        $request = new Net_DNS2_Packet_Request('example.com', 'SOA', 'IN');
        $str = (string)$request;

        $this->assertStringContainsString('Header:', $str);
        $this->assertStringContainsString('Question:', $str);
        $this->assertStringContainsString('example.com', $str);
    }

    public function testNameCompression(): void
    {
        $packet = new Net_DNS2_Packet_Request('example.com', 'A', 'IN');
        $offset = 0;

        $comp1 = $packet->compress('www.example.com', $offset);
        $comp2 = $packet->compress('mail.example.com', $offset);

        $this->assertNotEmpty($comp1);
        $this->assertNotEmpty($comp2);
        $this->assertLessThan(strlen($comp1) + strlen('mail.example.com') + 2, strlen($comp1) + strlen($comp2));
    }

    public function testStaticPack(): void
    {
        $packed = Net_DNS2_Packet::pack('example.com');
        $this->assertNotEmpty($packed);
        $this->assertStringEndsWith("\0", $packed);
    }
}
