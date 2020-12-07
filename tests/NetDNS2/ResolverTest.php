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
 * This test uses the Google public DNS servers to perform a resolution test;
 * this should work on *nix and Windows, but will require an internet connection.
 *
 */
class ResolverTest extends \PHPUnit\Framework\TestCase
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
        try
        {
            $r = new \NetDNS2\Resolver([ 'nameservers' => [ '8.8.8.8', '8.8.4.4' ] ]);

            $result = $r->query('google.com', 'MX');

            $this->assertSame($result->header->qr, \NetDNS2\Lookups::QR_RESPONSE, 
                sprintf('ResolverTest::testResolver(): %d != %d', $result->header->qr, \NetDNS2\Lookups::QR_RESPONSE));

            $this->assertSame(count($result->question), 1, 
                sprintf('ResolverTest::testResolver(): question count (%d) != 1', count($result->question)));

            $this->assertTrue(count($result->answer) > 0,
                sprintf('ResolverTest::testResolver(): answer count (%d) is not > 0', count($result->answer)));

            $this->assertTrue($result->answer[0] instanceof \NetDNS2\RR\MX,
                sprintf('ResolverTest::testResolver(): answer is not an MX record'));

        } catch(\NetDNS2\Exception $e)
        {
            $this->assertTrue(false, sprintf('ResolverTest::testResolver(): exception thrown: %s', $e->getMessage()));
        }
    }
}
