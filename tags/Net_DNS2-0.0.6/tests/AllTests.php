<?php

if (!defined('PHPUnit_MAIN_METHOD')) {
    define('PHPUnit_MAIN_METHOD', 'Net_DNS2_AllTests::main');
}

require_once 'PHPUnit/TextUI/TestRunner.php';
require_once 'Net_DNS2_ParserTest.php';
require_once 'Net_DNS2_ResolverTest.php';

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

        return $suite;
    }
}

if (PHPUnit_MAIN_METHOD == 'Net_DNS2_AllTests::main') {
    Net_DNS2_AllTests::main();
}

?>
