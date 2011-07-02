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
$pkg->setAPIVersion('1.1.3');
$pkg->setReleaseVersion('1.1.3');
$pkg->setReleaseStability('stable');
$pkg->setAPIStability('stable');
$pkg->setNotes("- added support for IPv6 DNS servers; from resolv.conf files, and from name server arrays\n- added new IPv4 and IPv6 validation functions, and a IPv6 expand function\n- changed the A, AAAA and IPSECKEY RR's to use the new validation methods\n- added support for IPv6 PTR records\n- dropped the old IPv4 regex from the lookups class\n");
$pkg->setPackageType('php');
$pkg->addRelease();
$pkg->setPhpDep('5.1.2');
$pkg->setPearinstallerDep('1.4.0a12');
$pkg->addMaintainer('lead', 'mikepultz', 'Mike Pultz', 'mike@mikepultz.com');
$pkg->setLicense('BSD License', 'http://www.opensource.org/licenses/bsd-license.php');
$pkg->generateContents();

$pkg->writePackageFile();

?>
