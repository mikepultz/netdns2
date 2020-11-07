<?php

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   NetDNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 * @since     File available since Release 1.0.0
 *
 */

namespace NetDNS2\Tests;

/**
 * Test class to test the DNSSEC logic
 *
 */
class DNSSECTest extends \PHPUnit\Framework\TestCase
{
    /**
     * function to test the TSIG logic
     *
     * @return void
     * @access public
     *
     */
    public function testDNSSEC()
    {
        try
        {
            $r = new \NetDNS2\Resolver([ 'nameservers' => [ '8.8.8.8', '8.8.4.4' ] ]);

            $r->dnssec = true;

            $result = $r->query('org', 'SOA', 'IN');

            $this->assertTrue(($result->header->ad == 1));
            $this->assertTrue(($result->additional[0] instanceof \NetDNS2\RR\OPT));
            $this->assertTrue(($result->additional[0]->do == 1));

        } catch(\NetDNS2\Exception $e)
        {
            // TODO what to do here?
            $this->assertTrue(false);
        }
    }
}
