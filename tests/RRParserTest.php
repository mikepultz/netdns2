<?php declare(strict_types=1);

namespace Net\DNS2\Tests;

use Net\DNS2\RR\RR;
use Net\DNS2\RR\A;
use Net\DNS2\RR\MX;
use Net\DNS2\RR\NS;
use Net\DNS2\Packet\Request;
use Net\DNS2\Packet\Response;
use Net\DNS2\Exception;
use PHPUnit\Framework\TestCase;

class RRParserTest extends TestCase
{
    #[\PHPUnit\Framework\Attributes\DataProvider('rrProvider')]
    public function testRRRoundTrip(string $type, string $line, string $expectedClass): void
    {
        $a = RR::fromString($line);
        $this->assertInstanceOf($expectedClass, $a);

        $request = new Request(
            $type === 'PTR' ? '1.0.0.127.in-addr.arpa' : 'example.com', $type, 'IN'
        );
        $request->answer[] = $a;
        $request->header->ancount = 1;

        $data = $request->get();
        $response = new Response($data, strlen($data));

        $this->assertSame($line, $response->answer[0]->__toString());
    }

    public static function rrProvider(): array
    {
        return [
            'A'     => ['A', 'example.com. 300 IN A 172.168.0.50', \Net\DNS2\RR\A::class],
            'NS'    => ['NS', 'example.com. 300 IN NS ns1.mrdns.com.', \Net\DNS2\RR\NS::class],
            'CNAME' => ['CNAME', 'example.com. 300 IN CNAME www.example.com.', \Net\DNS2\RR\CNAME::class],
            'SOA'   => ['SOA', 'example.com. 300 IN SOA ns1.mrdns.com. help\.team.mrhost.ca. 1278700841 900 1800 86400 21400', \Net\DNS2\RR\SOA::class],
            'PTR'   => ['PTR', '1.0.0.127.in-addr.arpa. 300 IN PTR localhost.', \Net\DNS2\RR\PTR::class],
            'MX'    => ['MX', 'example.com. 300 IN MX 10 mx1.mrhost.ca.', \Net\DNS2\RR\MX::class],
            'TXT'   => ['TXT', 'example.com. 300 IN TXT "first record" "another records" "a third"', \Net\DNS2\RR\TXT::class],
            'AAAA'  => ['AAAA', 'example.com. 300 IN AAAA 1080:0:0:0:8:800:200c:417a', \Net\DNS2\RR\AAAA::class],
            'SRV'   => ['SRV', 'example.com. 300 IN SRV 20 0 5269 xmpp-server2.l.google.com.', \Net\DNS2\RR\SRV::class],
            'DS'    => ['DS', 'example.com. 300 IN DS 21366 7 2 96eeb2ffd9b00cd4694e78278b5efdab0a80446567b69f634da078f0d90f01ba', \Net\DNS2\RR\DS::class],
            'DNSKEY'=> ['DNSKEY', 'example.com. 300 IN DNSKEY 256 3 7 AwEAAYCXh/ZABi8kiJIDXYmyUlHzC0CHeBzqcpyZAIjC7dK1wkRYVcUvIlpTOpnOVVfcC3Py9Ui/x45qKb0LytvK7WYAe3WyOOwk5klwIqRC/0p4luafbd2yhRMF7quOBVqYrLoHwv8i9LrV+r8dhB7rXv/lkTSI6mEZsg5rDfee8Yy1', \Net\DNS2\RR\DNSKEY::class],
            'CAA'   => ['CAA', 'example.com. 300 IN CAA 0 issue "ca.example.net; policy=ev"', \Net\DNS2\RR\CAA::class],
            'URI'   => ['URI', 'example.com. 300 IN URI 10 1 "http://mrdns.com/contact.html"', \Net\DNS2\RR\URI::class],
        ];
    }

    public function testTSIGRoundTrip(): void
    {
        $request = new Request('example.com', 'SOA', 'IN');
        $request->authority[] = RR::fromString('test.example.com A 10.10.10.10');
        $request->header->nscount = 1;
        $request->additional[] = RR::fromString('mykey TSIG Zm9vYmFy');
        $request->header->arcount = 1;

        $line = $request->additional[0]->name . '. ' .
            $request->additional[0]->ttl . ' ' .
            $request->additional[0]->class . ' ' .
            $request->additional[0]->type . ' ' .
            $request->additional[0]->algorithm . '. ' .
            $request->additional[0]->time_signed . ' ' .
            $request->additional[0]->fudge;

        $data = $request->get();
        $response = new Response($data, strlen($data));

        $this->assertSame($line, substr($response->additional[0]->__toString(), 0, 58));
    }

    public function testFromStringEmpty(): void
    {
        $this->expectException(Exception::class);
        RR::fromString('');
    }

    public function testRRAsArray(): void
    {
        $rr = RR::fromString('example.com. 300 IN A 1.2.3.4');
        $arr = $rr->asArray();
        $this->assertSame('example.com', $arr['name']);
        $this->assertSame(300, $arr['ttl']);
        $this->assertSame('IN', $arr['class']);
        $this->assertSame('A', $arr['type']);
    }

    public function testRRToString(): void
    {
        $rr = RR::fromString('example.com. 300 IN A 1.2.3.4');
        $this->assertSame('example.com. 300 IN A 1.2.3.4', (string)$rr);
    }
}
