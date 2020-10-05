<?php

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   Net_DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 * @since     File available since Release 1.0.0
 *
 */

require_once 'Net/DNS2.php';

/**
 * This test uses the Google public DNS servers to perform a resolution test;
 * this should work on *nix and Windows, but will require an internet connection.
 *
 */
class Tests_Net_DNS2_ResolverTest extends PHPUnit\Framework\TestCase
{
    /**
     * function to test the resolver
     *
     * @return void
     * @access public
     *
     */
    public function testResolver()
    {
        $ns = [ '8.8.8.8', '8.8.4.4' ];

        $r = new Net_DNS2_Resolver([ 'nameservers' => $ns ]);

        $result = $r->query('google.com', 'MX');

        $this->assertSame($result->header->qr, Net_DNS2_Lookups::QR_RESPONSE);
        $this->assertSame(count($result->question), 1);
        $this->assertTrue(count($result->answer) > 0);
        $this->assertTrue($result->answer[0] instanceof Net_DNS2_RR_MX);
    }
}
