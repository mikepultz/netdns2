<?php declare(strict_types=1);

require_once 'Net/DNS2.php';

use PHPUnit\Framework\TestCase;

class ExceptionTest extends TestCase
{
    public function testBasicException(): void
    {
        $e = new Net_DNS2_Exception('test error', 42);

        $this->assertSame('test error', $e->getMessage());
        $this->assertSame(42, $e->getCode());
        $this->assertNull($e->getRequest());
        $this->assertNull($e->getResponse());
    }

    public function testExceptionWithRequest(): void
    {
        $request = new Net_DNS2_Packet_Request('example.com', 'A', 'IN');

        $e = new Net_DNS2_Exception('test', 0, null, $request);

        $this->assertInstanceOf(Net_DNS2_Packet_Request::class, $e->getRequest());
        $this->assertNull($e->getResponse());
    }

    public function testExceptionWithPrevious(): void
    {
        $prev = new \RuntimeException('inner');
        $e = new Net_DNS2_Exception('outer', 0, $prev);

        $this->assertSame($prev, $e->getPrevious());
    }

    public function testExceptionInheritance(): void
    {
        $e = new Net_DNS2_Exception();

        $this->assertInstanceOf(\Exception::class, $e);
        $this->assertInstanceOf(\Throwable::class, $e);
    }
}
