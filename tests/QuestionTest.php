<?php declare(strict_types=1);

require_once 'Net/DNS2.php';

use PHPUnit\Framework\TestCase;

class QuestionTest extends TestCase
{
    public function testDefaultValues(): void
    {
        $q = new Net_DNS2_Question();

        $this->assertSame('', $q->qname);
        $this->assertSame('A', $q->qtype);
        $this->assertSame('IN', $q->qclass);
    }

    public function testToString(): void
    {
        $q = new Net_DNS2_Question();
        $q->qname = 'example.com';
        $q->qtype = 'MX';
        $q->qclass = 'IN';

        $str = (string)$q;
        $this->assertStringContainsString('example.com', $str);
        $this->assertStringContainsString('MX', $str);
        $this->assertStringContainsString('IN', $str);
    }

    public function testQuestionPackUnpack(): void
    {
        $request = new Net_DNS2_Packet_Request('example.com', 'AAAA', 'IN');
        $data = $request->get();
        $response = new Net_DNS2_Packet_Response($data, strlen($data));

        $this->assertCount(1, $response->question);
        $this->assertSame('example.com', $response->question[0]->qname);
        $this->assertSame('AAAA', $response->question[0]->qtype);
        $this->assertSame('IN', $response->question[0]->qclass);
    }
}
