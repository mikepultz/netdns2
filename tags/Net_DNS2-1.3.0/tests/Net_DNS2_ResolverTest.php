<?php

require_once 'Net/DNS2.php';

//
// This test uses the Google public DNS servers to perform a resolution test; this should work on
// *nix and Windows, but will require an internet connection.
//
class Net_DNS2_ResolverTest extends PHPUnit_Framework_TestCase
{
    public function testResolver()
    {
        $r = new Net_DNS2_Resolver(array('nameservers' => array('8.8.8.8', '8.8.4.4')));

        $result = $r->query('google.com', 'MX');

        $this->assertSame($result->header->qr, Net_DNS2_Lookups::QR_RESPONSE);
        $this->assertSame(count($result->question), 1);
        $this->assertTrue(count($result->answer) > 0);
        $this->assertTrue($result->answer[0] instanceof Net_DNS2_RR_MX);
    }
}

?>
