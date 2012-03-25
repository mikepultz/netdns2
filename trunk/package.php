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
$pkg->setAPIVersion('1.2.1');
$pkg->setReleaseVersion('1.2.1');
$pkg->setReleaseStability('stable');
$pkg->setAPIStability('stable');
$pkg->setNotes("- changed the Net_DNS2_Sockets::_sock property from private to protected; this was causing some problems when the request was failing.\n- PHP doesn't support unsigned integers, but many of the RR's return unsigned values (like SOA), so there is the possibility that the value will overrun on 32bit systems, and you'll end up with a negative value. So a new function was added to convert the negative value, to a string with the correct unsigned value.\n");
$pkg->setPackageType('php');
$pkg->addRelease();
$pkg->setPhpDep('5.1.2');
$pkg->setPearinstallerDep('1.4.0a12');
$pkg->addMaintainer('lead', 'mikepultz', 'Mike Pultz', 'mike@mikepultz.com');
$pkg->setLicense('BSD License', 'http://www.opensource.org/licenses/bsd-license.php');
$pkg->generateContents();

$pkg->writePackageFile();

?>
