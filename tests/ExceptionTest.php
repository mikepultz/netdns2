<?php declare(strict_types=1);

namespace Net\DNS2\Tests;

use Net\DNS2\Exception;
use Net\DNS2\Packet\Request;
use PHPUnit\Framework\TestCase;

class ExceptionTest extends TestCase
{
    public function testBasic(): void
    {
        $e = new Exception('test', 42);
        $this->assertSame('test', $e->getMessage());
        $this->assertSame(42, $e->getCode());
        $this->assertNull($e->getRequest());
        $this->assertNull($e->getResponse());
    }

    public function testWithRequest(): void
    {
        $req = new Request('example.com', 'A', 'IN');
        $e = new Exception('test', 0, null, $req);
        $this->assertInstanceOf(Request::class, $e->getRequest());
    }

    public function testInheritance(): void
    {
        $this->assertInstanceOf(\Exception::class, new Exception());
    }
}
