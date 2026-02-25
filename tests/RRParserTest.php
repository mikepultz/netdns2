<?php declare(strict_types=1);

require_once 'Net/DNS2.php';

use PHPUnit\Framework\TestCase;

/**
 * Test RR parsing from string and binary round-trip for all supported RR types
 */
class RRParserTest extends TestCase
{
    /**
     * @dataProvider rrProvider
     */
    public function testRRRoundTrip(string $type, string $line, string $expectedClass): void
    {
        $a = Net_DNS2_RR::fromString($line);

        $this->assertInstanceOf($expectedClass, $a, "fromString failed for {$type}");

        $request = new Net_DNS2_Packet_Request(
            $type === 'PTR' ? '1.0.0.127.in-addr.arpa' : 'example.com',
            $type,
            'IN'
        );
        $request->answer[] = $a;
        $request->header->ancount = 1;

        $data = $request->get();
        $response = new Net_DNS2_Packet_Response($data, strlen($data));

        $this->assertSame($line, $response->answer[0]->__toString(),
            "Round-trip failed for {$type}");
    }

    public static function rrProvider(): array
    {
        return [
            'A'         => ['A', 'example.com. 300 IN A 172.168.0.50', 'Net_DNS2_RR_A'],
            'NS'        => ['NS', 'example.com. 300 IN NS ns1.mrdns.com.', 'Net_DNS2_RR_NS'],
            'CNAME'     => ['CNAME', 'example.com. 300 IN CNAME www.example.com.', 'Net_DNS2_RR_CNAME'],
            'SOA'       => ['SOA', 'example.com. 300 IN SOA ns1.mrdns.com. help\.team.mrhost.ca. 1278700841 900 1800 86400 21400', 'Net_DNS2_RR_SOA'],
            'WKS'       => ['WKS', 'example.com. 300 IN WKS 128.8.1.14 6 21 25', 'Net_DNS2_RR_WKS'],
            'PTR'       => ['PTR', '1.0.0.127.in-addr.arpa. 300 IN PTR localhost.', 'Net_DNS2_RR_PTR'],
            'HINFO'     => ['HINFO', 'example.com. 300 IN HINFO "PC-Intel-700mhz" "Redhat \"Linux\" 7.1"', 'Net_DNS2_RR_HINFO'],
            'MX'        => ['MX', 'example.com. 300 IN MX 10 mx1.mrhost.ca.', 'Net_DNS2_RR_MX'],
            'TXT'       => ['TXT', 'example.com. 300 IN TXT "first record" "another records" "a third"', 'Net_DNS2_RR_TXT'],
            'AAAA'      => ['AAAA', 'example.com. 300 IN AAAA 1080:0:0:0:8:800:200c:417a', 'Net_DNS2_RR_AAAA'],
            'SRV'       => ['SRV', 'example.com. 300 IN SRV 20 0 5269 xmpp-server2.l.google.com.', 'Net_DNS2_RR_SRV'],
            'DNAME'     => ['DNAME', 'example.com. 300 IN DNAME frobozz-division.acme.example.', 'Net_DNS2_RR_DNAME'],
            'DS'        => ['DS', 'example.com. 300 IN DS 21366 7 2 96eeb2ffd9b00cd4694e78278b5efdab0a80446567b69f634da078f0d90f01ba', 'Net_DNS2_RR_DS'],
            'SSHFP'     => ['SSHFP', 'example.com. 300 IN SSHFP 2 1 123456789abcdef67890123456789abcdef67890', 'Net_DNS2_RR_SSHFP'],
            'NSEC'      => ['NSEC', 'example.com. 300 IN NSEC dog.poo.com. A MX RRSIG NSEC TYPE1234', 'Net_DNS2_RR_NSEC'],
            'DNSKEY'    => ['DNSKEY', 'example.com. 300 IN DNSKEY 256 3 7 AwEAAYCXh/ZABi8kiJIDXYmyUlHzC0CHeBzqcpyZAIjC7dK1wkRYVcUvIlpTOpnOVVfcC3Py9Ui/x45qKb0LytvK7WYAe3WyOOwk5klwIqRC/0p4luafbd2yhRMF7quOBVqYrLoHwv8i9LrV+r8dhB7rXv/lkTSI6mEZsg5rDfee8Yy1', 'Net_DNS2_RR_DNSKEY'],
            'DHCID'     => ['DHCID', 'example.com. 300 IN DHCID AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=', 'Net_DNS2_RR_DHCID'],
            'NSEC3PARAM'=> ['NSEC3PARAM', 'example.com. 300 IN NSEC3PARAM 1 0 1 D399EAAB', 'Net_DNS2_RR_NSEC3PARAM'],
            'SPF'       => ['SPF', 'example.com. 300 IN SPF "v=spf1 ip4:192.168.0.1/24 mx ?all"', 'Net_DNS2_RR_SPF'],
            'NID'       => ['NID', 'example.com. 300 IN NID 10 14:4fff:ff20:ee64', 'Net_DNS2_RR_NID'],
            'L32'       => ['L32', 'example.com. 300 IN L32 10 10.1.2.0', 'Net_DNS2_RR_L32'],
            'URI'       => ['URI', 'example.com. 300 IN URI 10 1 "http://mrdns.com/contact.html"', 'Net_DNS2_RR_URI'],
            'CAA'       => ['CAA', 'example.com. 300 IN CAA 0 issue "ca.example.net; policy=ev"', 'Net_DNS2_RR_CAA'],
        ];
    }

    public function testTSIGRoundTrip(): void
    {
        $request = new Net_DNS2_Packet_Request('example.com', 'SOA', 'IN');
        $request->authority[] = Net_DNS2_RR::fromString('test.example.com A 10.10.10.10');
        $request->header->nscount = 1;
        $request->additional[] = Net_DNS2_RR::fromString('mykey TSIG Zm9vYmFy');
        $request->header->arcount = 1;

        $line = $request->additional[0]->name . '. ' .
            $request->additional[0]->ttl . ' ' .
            $request->additional[0]->class . ' ' .
            $request->additional[0]->type . ' ' .
            $request->additional[0]->algorithm . '. ' .
            $request->additional[0]->time_signed . ' ' .
            $request->additional[0]->fudge;

        $data = $request->get();
        $response = new Net_DNS2_Packet_Response($data, strlen($data));

        $this->assertSame($line, substr($response->additional[0]->__toString(), 0, 58));
    }

    public function testFromStringEmpty(): void
    {
        $this->expectException(Net_DNS2_Exception::class);
        Net_DNS2_RR::fromString('');
    }

    public function testFromStringTooShort(): void
    {
        $this->expectException(Net_DNS2_Exception::class);
        Net_DNS2_RR::fromString('name');
    }

    public function testRRAsArray(): void
    {
        $rr = Net_DNS2_RR::fromString('example.com. 300 IN A 1.2.3.4');
        $arr = $rr->asArray();

        $this->assertSame('example.com', $arr['name']);
        $this->assertSame(300, $arr['ttl']);
        $this->assertSame('IN', $arr['class']);
        $this->assertSame('A', $arr['type']);
        $this->assertSame('1.2.3.4', $arr['rdata']);
    }

    public function testRRToString(): void
    {
        $rr = Net_DNS2_RR::fromString('example.com. 300 IN A 1.2.3.4');
        $this->assertSame('example.com. 300 IN A 1.2.3.4', (string)$rr);
    }
}
