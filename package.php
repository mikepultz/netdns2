<?php

date_default_timezone_set('America/Toronto');

ini_set("include_path", ".:/usr/local/php/lib/php/:/usr/share/pear/");
require_once 'PEAR/PackageFileManager/File.php';
require_once 'PEAR/PackageFileManager2.php';

$pkg = new PEAR_PackageFileManager2;

$e = $pkg->setOptions([
        
        'baseinstalldir'    => '/',
        'packagedirectory'  => '/u/devel/net_dns/Net_DNS2/',
        'ignore'            => [
            'package.php',
            'package.xml',
            'TODO',
            'composer.json'
        ],
        'installexceptions' => [ 'phpdoc' => '/*' ],
        'dir_roles'         => [
            'tests'     => 'test'
        ],
        'exceptions'        => [
            'LICENSE'   => 'doc',
            'README.md' => 'doc'
        ]
]);

$pkg->setPackage('Net_DNS2');
$pkg->setSummary('PHP Resolver library used to communicate with a DNS server.');
$pkg->setDescription("Provides (roughly) the same functionality as Net_DNS, but using modern PHP objects, exceptions for error handling, better sockets support.\n\nThis release is (in most cases) 2x - 10x faster than Net_DNS, as well as includes more RR's (including DNSSEC RR's), and improved sockets and streams support.");
$pkg->setChannel('pear.php.net');
$pkg->setAPIVersion('1.5.0');
$pkg->setReleaseVersion('1.5.0');
$pkg->setReleaseStability('stable');
$pkg->setAPIStability('stable');
$pkg->setNotes(
"- added the AMTRELAY resource record type (RFC 8777).\n" .
"- added Net_DNS2_RR::asArray(), which returns the same values as __toString(), but as an array for easier access.\n" .
"- added Net_DNS2::closeSockets(), which lets you close all cached network sockets in the resolver object.\n" .
"- added Net_DNS2::getSockets(), which returns the local sockets cache array.\n" .
"- added date_created and date_last_used to the Net_DNS2_Socket object, to track usage stats on each socket object.\n" .
"- added the SHA256, SHA384, and GOST digest defines to Lookups.php.\n" .
"- dropped the Net_DNS2_Socket_Sockets, and switch to just using the streams code. There's no speed difference anymore.\n" .
"- fixed a bug in Net_DNS2_Packet::compress() and Net_DNS2_Packet::expand() related to dot literals in compressed names.\n" .
"- fixed a display issue in the IPSECKEY RR when displaying hostname / domain names in the gateway field.\n" .
"- fixed a couple inconsistencies in the docs.\n" .
"- fixed a PHP 7.4 bug in Sockets.php; accessing a null value as an array throws an exception now.\n" .
"- fixed Net_DNS2_RR_DS so it will be able to support other digest definitions without any other changes.\n" .
"- the Net_DNS2_RR_NIMLOC class was incorrectly named Net_DNS2_RR_NIMLOCK.\n" .
"- Net_DNS2_PrivateKey was using the wrong member variable name for the key_format value.\n" .
"- changed all references to array() to [].\n" .
"- removed all sorts of license noise from the files.\n" .
"- updated the test cases to use PHPUnit v9+.\n"
);
$pkg->setPackageType('php');
$pkg->addRelease();
$pkg->setPhpDep('5.4');
$pkg->setPearinstallerDep('1.4.0a12');
$pkg->addMaintainer('lead', 'mikepultz', 'Mike Pultz', 'mike@mikepultz.com');
$pkg->setLicense('BSD License', 'http://www.opensource.org/licenses/bsd-license.php');
$pkg->generateContents();

$pkg->writePackageFile();
