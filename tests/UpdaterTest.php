<?php declare(strict_types=1);

namespace Net\DNS2\Tests;

use Net\DNS2\Updater;
use Net\DNS2\Lookups;
use Net\DNS2\RR\RR;
use Net\DNS2\Exception;
use PHPUnit\Framework\TestCase;

class UpdaterTest extends TestCase
{
    private function makeUpdater(): Updater
    {
        return new Updater('example.com', ['nameservers' => ['10.10.0.1']]);
    }

    public function testCreation(): void
    {
        $this->assertInstanceOf(Updater::class, $this->makeUpdater());
    }

    public function testAddRR(): void
    {
        $u = $this->makeUpdater();
        $rr = RR::fromString('test.example.com A 10.10.10.10');
        $u->add($rr);
        $p = $u->packet();
        $this->assertCount(1, $p->authority);
        $this->assertSame('test.example.com', $p->authority[0]->name);
    }

    public function testDeleteRR(): void
    {
        $u = $this->makeUpdater();
        $rr = RR::fromString('test.example.com A 10.10.10.10');
        $u->delete($rr);
        $p = $u->packet();
        $this->assertSame(0, $p->authority[0]->ttl);
        $this->assertSame('NONE', $p->authority[0]->class);
    }

    public function testDeleteAny(): void
    {
        $u = $this->makeUpdater();
        $u->deleteAny('test.example.com', 'A');
        $p = $u->packet();
        $this->assertSame('ANY', $p->authority[0]->class);
    }

    public function testCheckExists(): void
    {
        $u = $this->makeUpdater();
        $u->checkExists('test.example.com', 'A');
        $p = $u->packet();
        $this->assertSame('ANY', $p->answer[0]->class);
    }

    public function testCheckNotExists(): void
    {
        $u = $this->makeUpdater();
        $u->checkNotExists('test.example.com', 'A');
        $p = $u->packet();
        $this->assertSame('NONE', $p->answer[0]->class);
    }

    public function testInvalidNameThrows(): void
    {
        $u = $this->makeUpdater();
        $rr = RR::fromString('test.other.com A 10.10.10.10');
        $this->expectException(Exception::class);
        $u->add($rr);
    }

    public function testPacketOpcode(): void
    {
        $p = $this->makeUpdater()->packet();
        $this->assertSame(Lookups::OPCODE_UPDATE, $p->header->opcode);
    }
}
