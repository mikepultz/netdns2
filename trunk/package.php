<?php

ini_set("include_path", ".:/usr/local/php/lib/php/:/usr/local/php/lib/php/PEAR/PackageFileManager");
require_once 'PEAR/PackageFileManager/File.php';
require_once 'PEAR/PackageFileManager2.php';

$pkg = new PEAR_PackageFileManager2;

$e = $pkg->setOptions(

    array(

        'baseinstalldir'    => '/',
        'packagedirectory'  => '/u/devel/www/Net_DNS2/',
        'ignore' => array('TODO', 'tests/', 'package.php', 'docs/'),
        'installexceptions' => array('phpdoc' => '/*'),
        'dir_roles' => array('tutorials' => 'doc'),
));

$pkg->setPackage('Net_DNS2');
$pkg->setSummary('PHP5 Resolver library used to communicate with a DNS server.');
$pkg->setDescription("Provides (roughly) the same functionality as Net_DNS, but using PHP5 objects, exceptions for error handling, better sockets support.\n\nThis release is (in most cases) 2x - 10x faster than Net_DNS, as well as includes more RR's (including DNSSEC RR's), and improved sockets and streams support.");
$pkg->setChannel('pear.php.net');
$pkg->setAPIVersion('1.2.2');
$pkg->setReleaseVersion('1.2.2');
$pkg->setReleaseStability('stable');
$pkg->setAPIStability('stable');
$pkg->setNotes("- added some trimming of whitespace to Net_DNS2_RR::buildString(); we'd get some Uninitialized string offset errors if there was some blank space at the end.\n- fixed a few cases where Net_DNS2_Lookup where it should Net_DNS2_Lookups\n- added support for a strict query mode, that lets you handle the weird way DNS handles failed lookups + CNAME recors; see RFC 1034 section 3.6.2 for more information.\n- fixed some warning messages that were coming from the cache classes when a json_decode() would fail.\n- fixed a bug in Net_DNS2_Cache_File and Net_DNS2_Cache_Shm; it would try to write the file even if caching was turned off\n- made sure we don't cache records when we do a zone transfer\n- added some blocking in both the Sockets.php and Streams.php file around the read function\n- I wasn't handling multi-message zone transfers properly; now we loop through and read all the messages and pack them together as one big result\n");
$pkg->setPackageType('php');
$pkg->addRelease();
$pkg->setPhpDep('5.1.2');
$pkg->setPearinstallerDep('1.4.0a12');
$pkg->addMaintainer('lead', 'mikepultz', 'Mike Pultz', 'mike@mikepultz.com');
$pkg->setLicense('BSD License', 'http://www.opensource.org/licenses/bsd-license.php');
$pkg->generateContents();

$pkg->writePackageFile();

?>
