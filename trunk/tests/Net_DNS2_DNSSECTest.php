<?php

require_once 'Net/DNS2.php';

class Net_DNS2_DNSSECTest extends PHPUnit_Framework_TestCase
{
    public function testTSIG()
    {
        $r = new Net_DNS2_Resolver(array('nameservers' => array('8.8.8.8', '8.8.4.4')));

        $r->dnssec = true;

        $result = $r->query('org', 'SOA', 'IN');

        $this->assertTrue(($result->header->ad == 1));
        $this->assertTrue(($result->additional[0] instanceof Net_DNS2_RR_OPT));
        $this->assertTrue(($result->additional[0]->do == 1));
    }
};

?>
