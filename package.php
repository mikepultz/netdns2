<?php

date_default_timezone_set('America/Toronto');

ini_set("include_path", ".:/usr/local/php/lib/php/:/usr/local/php/lib/php/PEAR/PackageFileManager");
require_once 'PEAR/PackageFileManager/File.php';
require_once 'PEAR/PackageFileManager2.php';

$pkg = new PEAR_PackageFileManager2;

$e = $pkg->setOptions(array(
        
        'baseinstalldir'    => '/',
        'packagedirectory'  => '/u/devel/www/Net_DNS2/',
        'ignore'            => array(
            'package.php',
            'package.xml',
            'TODO',
            'composer.json'
        ),
        'installexceptions' => array('phpdoc' => '/*'),
        'dir_roles'         => array(
            'tests'     => 'test'
        ),
        'exceptions'        => array(
            'LICENSE'   => 'doc'
        )
));

$pkg->setPackage('Net_DNS2');
$pkg->setSummary('PHP5 Resolver library used to communicate with a DNS server.');
$pkg->setDescription("Provides (roughly) the same functionality as Net_DNS, but using PHP5 objects, exceptions for error handling, better sockets support.\n\nThis release is (in most cases) 2x - 10x faster than Net_DNS, as well as includes more RR's (including DNSSEC RR's), and improved sockets and streams support.");
$pkg->setChannel('pear.php.net');
$pkg->setAPIVersion('1.4.1');
$pkg->setReleaseVersion('1.4.1');
$pkg->setReleaseStability('stable');
$pkg->setAPIStability('stable');
$pkg->setNotes(
"- increased the default DNSSEC payload size value to 4000 bytes per RFC 4035 section 4.1; this is still configurable.\n" .
"- fixed a bug where I was still using the DNS_MAX_UDP_SIZE default (512 bytes) for all requests, event DNSSEC, where I should have been using the dnssec_payload_size config value.\n" .
"- removed the limitation that PTR records had to look like IP addresses; you can add other things to PTR records, like service discovery objects- RFC 6763.\n" .
"- dropped support for using the Sockets library on Windows. There have been too many inconsistencies between versions of Windows; we'll just default to use the Streams library.\n" .
"- fixed the Net_DNS2_RR_PTR class so we can pass ptrdname's with spaces in them so that we can support DNS-Based Service Discovery (RFC 6763).\n" .
"- added support for the CSYNC resource record - see RFC 7477.\n"
);
$pkg->setPackageType('php');
$pkg->addRelease();
$pkg->setPhpDep('5.1.2');
$pkg->setPearinstallerDep('1.4.0a12');
$pkg->addMaintainer('lead', 'mikepultz', 'Mike Pultz', 'mike@mikepultz.com');
$pkg->setLicense('BSD License', 'http://www.opensource.org/licenses/bsd-license.php');
$pkg->generateContents();

$pkg->writePackageFile();

?>
