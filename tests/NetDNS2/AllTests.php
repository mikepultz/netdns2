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

use \NetDNS2\Tests\ParserTest;
use \NetDNS2\Tests\ResolverTest;
use \NetDNS2\Tests\DNSSECTest;

error_reporting(E_ALL | E_STRICT);

if (defined('PHPUNIT_MAIN_METHOD') == false)
{
    define('PHPUNIT_MAIN_METHOD', '\NetDNS2\Tests\AllTests::main');
}

set_include_path('..:.:src/');

echo "ALLTESTS\n";

/**
 * This test suite assumes that Net_DNS2 will be in the include path, otherwise it
 * will fail. There's no other way to hardcode a include_path in here that would
 * make it work everywhere.
 *
 */
class AllTests
{
    /**
     * the main runner
     *
     * @return void
     * @access public
     *
     */
    public static function main()
    {
        PHPUnit_TextUI_TestRunner::run(self::suite());
    }

    /**
     * test suite
     *
     * @return void
     * @access public
     *
     */
    public static function suite()
    {
        $suite = new PHPUnit_Framework_TestSuite('PEAR - NetDNS2');

        $suite->addTestSuite('\NetDNS2\Tests\ParserTest');
        $suite->addTestSuite('\NetDNS2\Tests\ResolverTest');
        $suite->addTestSuite('\NetDNS2\Tests\DNSSECTest');

        return $suite;
    }
}

if (PHPUNIT_MAIN_METHOD == '\NetDNS2\Tests\AllTests::main')
{
    \NetDNS2\Tests\AllTests::main();
}
