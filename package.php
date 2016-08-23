<?php

date_default_timezone_set('America/Toronto');

ini_set("include_path", ".:/usr/local/php/lib/php/:/usr/share/pear/");
require_once 'PEAR/PackageFileManager/File.php';
require_once 'PEAR/PackageFileManager2.php';

$pkg = new PEAR_PackageFileManager2;

$e = $pkg->setOptions(array(
        
        'baseinstalldir'    => '/',
        'packagedirectory'  => '/u/devel/www/net_dns/Net_DNS2/',
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
            'LICENSE'   => 'doc',
            'README.md' => 'doc'
        )
));

$pkg->setPackage('Net_DNS2');
$pkg->setSummary('PHP5 Resolver library used to communicate with a DNS server.');
$pkg->setDescription("Provides (roughly) the same functionality as Net_DNS, but using PHP5 objects, exceptions for error handling, better sockets support.\n\nThis release is (in most cases) 2x - 10x faster than Net_DNS, as well as includes more RR's (including DNSSEC RR's), and improved sockets and streams support.");
$pkg->setChannel('pear.php.net');
$pkg->setAPIVersion('1.4.2');
$pkg->setReleaseVersion('1.4.2');
$pkg->setReleaseStability('stable');
$pkg->setAPIStability('stable');
$pkg->setNotes(
"- changed the role for the README.md file to doc\n" .
"- parse the resolv.conf options line; right now I just support the timeout and rotate options.\n" .
"- the options values only work if you set the new option use_resolv_options to true; this is to keep backwards compatibility.\n" .
"- added support for RFC 6594; support for SHA-256 and ECDSA in the SSHFP resource record.\n" .
"- added the SMIMEA resource record; this just extends the TLSA record.\n" .
"- added the AVC resource records; this just extends the TXT record.\n" .
"- added error and EDNS0 defines for DNS Cookies (RFC7873)\n" .
"- added EDNS0 defines to the lookup class\n" .
"- dropped the Net_DNS2_Packet::formatIPv6() function; this was deprecated in v1.1.3\n" .
"- re-wrote the Net_DNS2::expandIPv6() function. Based on testing, the new version is about twice as fast.\n"
);
$pkg->setPackageType('php');
$pkg->addRelease();
$pkg->setPhpDep('5.2.1');
$pkg->setPearinstallerDep('1.4.0a12');
$pkg->addMaintainer('lead', 'mikepultz', 'Mike Pultz', 'mike@mikepultz.com');
$pkg->setLicense('BSD License', 'http://www.opensource.org/licenses/bsd-license.php');
$pkg->generateContents();

$pkg->writePackageFile();

?>
