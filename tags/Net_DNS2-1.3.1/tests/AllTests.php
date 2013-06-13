<?php

//
// This test suite assumes that Net_DNS2 will be in the include path, otherwise it
// will fail. There's no other way to hardcode a include_path in here that would make
// it work everywhere.
//

error_reporting(E_ALL | E_STRICT);

if (!defined('PHPUnit_MAIN_METHOD')) {
    define('PHPUnit_MAIN_METHOD', 'Net_DNS2_AllTests::main');
}

require_once 'PHPUnit/TextUI/TestRunner.php';
require_once 'Net_DNS2_ParserTest.php';
require_once 'Net_DNS2_ResolverTest.php';
require_once 'Net_DNS2_DNSSECTest.php';

class Net_DNS2_AllTests
{
    public static function main()
    {
        PHPUnit_TextUI_TestRunner::run(self::suite());
    }
    public static function suite()
    {
        $suite = new PHPUnit_Framework_TestSuite('PEAR - Net_DNS2');

        $suite->addTestSuite('Net_DNS2_ParserTest');
        $suite->addTestSuite('Net_DNS2_ResolverTest');
        $suite->addTestSuite('Net_DNS2_DNSSECTest');

        return $suite;
    }
}

if (PHPUnit_MAIN_METHOD == 'Net_DNS2_AllTests::main') {
    Net_DNS2_AllTests::main();
}

?>
