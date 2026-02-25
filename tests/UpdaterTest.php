<?php declare(strict_types=1);

require_once 'Net/DNS2.php';

use PHPUnit\Framework\TestCase;

class UpdaterTest extends TestCase
{
    private function makeUpdater(): Net_DNS2_Updater
    {
        return new Net_DNS2_Updater('example.com', [
            'nameservers' => ['10.10.0.1'],
        ]);
    }

    public function testUpdaterCreation(): void
    {
        $u = $this->makeUpdater();
        $this->assertInstanceOf(Net_DNS2_Updater::class, $u);
    }

    public function testAddRR(): void
    {
        $u = $this->makeUpdater();
        $rr = Net_DNS2_RR::fromString('test.example.com A 10.10.10.10');
        $result = $u->add($rr);

        $this->assertTrue($result);

        $packet = $u->packet();
        $this->assertCount(1, $packet->authority);
        $this->assertSame('test.example.com', $packet->authority[0]->name);
    }

    public function testAddDuplicateRR(): void
    {
        $u = $this->makeUpdater();
        $rr = Net_DNS2_RR::fromString('test.example.com A 10.10.10.10');

        $u->add($rr);
        $u->add($rr);

        $packet = $u->packet();
        $this->assertCount(1, $packet->authority);
    }

    public function testDeleteRR(): void
    {
        $u = $this->makeUpdater();
        $rr = Net_DNS2_RR::fromString('test.example.com A 10.10.10.10');
        $u->delete($rr);

        $packet = $u->packet();
        $this->assertSame(0, $packet->authority[0]->ttl);
        $this->assertSame('NONE', $packet->authority[0]->class);
    }

    public function testDeleteAny(): void
    {
        $u = $this->makeUpdater();
        $u->deleteAny('test.example.com', 'A');

        $packet = $u->packet();
        $this->assertSame(0, $packet->authority[0]->ttl);
        $this->assertSame('ANY', $packet->authority[0]->class);
        $this->assertSame(-1, $packet->authority[0]->rdlength);
    }

    public function testDeleteAll(): void
    {
        $u = $this->makeUpdater();
        $u->deleteAll('test.example.com');

        $packet = $u->packet();
        $this->assertSame('ANY', $packet->authority[0]->type);
        $this->assertSame('ANY', $packet->authority[0]->class);
    }

    public function testCheckExists(): void
    {
        $u = $this->makeUpdater();
        $u->checkExists('test.example.com', 'A');

        $packet = $u->packet();
        $this->assertCount(1, $packet->answer);
        $this->assertSame('ANY', $packet->answer[0]->class);
    }

    public function testCheckNotExists(): void
    {
        $u = $this->makeUpdater();
        $u->checkNotExists('test.example.com', 'A');

        $packet = $u->packet();
        $this->assertCount(1, $packet->answer);
        $this->assertSame('NONE', $packet->answer[0]->class);
    }

    public function testCheckNameInUse(): void
    {
        $u = $this->makeUpdater();
        $u->checkNameInUse('test.example.com');

        $packet = $u->packet();
        $this->assertSame('ANY', $packet->answer[0]->type);
        $this->assertSame('ANY', $packet->answer[0]->class);
    }

    public function testCheckNameNotInUse(): void
    {
        $u = $this->makeUpdater();
        $u->checkNameNotInUse('test.example.com');

        $packet = $u->packet();
        $this->assertSame('ANY', $packet->answer[0]->type);
        $this->assertSame('NONE', $packet->answer[0]->class);
    }

    public function testInvalidNameThrows(): void
    {
        $u = $this->makeUpdater();
        $rr = Net_DNS2_RR::fromString('test.other.com A 10.10.10.10');

        $this->expectException(Net_DNS2_Exception::class);
        $u->add($rr);
    }

    public function testPacketOpcode(): void
    {
        $u = $this->makeUpdater();
        $packet = $u->packet();

        $this->assertSame(Net_DNS2_Lookups::OPCODE_UPDATE, $packet->header->opcode);
    }

    public function testPacketCounts(): void
    {
        $u = $this->makeUpdater();
        $u->add(Net_DNS2_RR::fromString('test.example.com A 10.10.10.10'));
        $u->checkExists('test.example.com', 'MX');

        $packet = $u->packet();

        $this->assertSame(1, $packet->header->qdcount);
        $this->assertSame(1, $packet->header->ancount);
        $this->assertSame(1, $packet->header->nscount);
    }
}
