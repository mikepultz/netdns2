<?php

/**
 * This file is part of the NetDNS2 package.
 *
 * (c) Mike Pultz <mike@mikepultz.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 */

namespace NetDNS2\Tests;

/**
 * test class to exercise RR::fromString() error paths
 *
 */
class RRTest extends \PHPUnit\Framework\TestCase
{
    /**
     * function to test that fromString() throws on an empty input string
     *
     * @return void
     * @access public
     *
     */
    public function testFromStringEmptyThrows()
    {
        $this->expectException(\NetDNS2\Exception::class);

        \NetDNS2\RR::fromString('');
    }

    /**
     * function to test that fromString() throws when fewer than 3 whitespace-separated tokens are given
     *
     * The minimum valid line requires at least 3 tokens (name, type, and rdata);
     * two tokens is not enough.
     *
     * @return void
     * @access public
     *
     */
    public function testFromStringTooFewTokensThrows()
    {
        $this->expectException(\NetDNS2\Exception::class);

        \NetDNS2\RR::fromString('example.com A');
    }

    /**
     * function to test that fromString() throws when an unrecognised token appears where a type mnemonic is expected
     *
     * @return void
     * @access public
     *
     */
    public function testFromStringUnknownTypeThrows()
    {
        $this->expectException(\NetDNS2\Exception::class);

        \NetDNS2\RR::fromString('example.com 300 IN BADTYPE somedata');
    }
}
