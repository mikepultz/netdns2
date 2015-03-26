<?php

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
"- increased the default DNSSEC payload size value to 4000 bytes per RFC 4035 section 4.1; this is still configurable" .
"- fixed a bug where I was still using the DNS_MAX_UDP_SIZE default (512 bytes) for all requests, event DNSSEC, where I should have been using the dnssec_payload_size config value" .
"- removed the limitation that PTR records had to look like IP addresses; you can add other things to PTR records, like service discovery objects- RFC 6763"
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
