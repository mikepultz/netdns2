<?php

require_once 'Net/DNS2.php';

//
// This test requires a /etc/resolv.conf file to work- so it will unfortunately
// break on windows machines.
//
class Net_DNS2_ResolverTest extends PHPUnit_Framework_TestCase
{
    public function testResolver()
    {
        $r = new Net_DNS2_Resolver(array('nameservers' => '/etc/resolv.conf'));

        $result = $r->query('google.com', 'MX');

        $this->assertSame($result->header->qr, Net_DNS2_Lookups::QR_RESPONSE);
        $this->assertSame(count($result->question), 1);
        $this->assertTrue(count($result->answer) > 0);
        $this->assertTrue($result->answer[0] instanceof Net_DNS2_RR_MX);
    }
}

?>
