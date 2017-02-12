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
$pkg->setAPIVersion('1.4.3');
$pkg->setReleaseVersion('1.4.3');
$pkg->setReleaseStability('stable');
$pkg->setAPIStability('stable');
$pkg->setNotes(
"- fixed an issue when looking up . or com., when using the strict_query_mode flag.\n" .
"- fixed a bug in the caching logic where I was loading the content more than once per instance, when really I only need to do it once.\n" .
"- changed the Net_DNS2::sock array to use the SOCK_DGRAM and SOCK_STREAM defines, rather than the strings 'tcp' or 'udp'.\n" .
"- fixed a bug in the Net_DNS2_Header and Net_DNS2_Question classes, where I was using the wrong bit-shift operators when parsing some of the values. This only became apparent when somebody was trying to use the CAA class (id 257); it was causing this to roll over to the next 8 bit value, and returning 1 (RR A) instead of the CAA class.\n" .
"- fixed a bug that occurs when a DNS lookup request times out, and then the same class is reused for a subsequent request. Because I'm caching the sockets, the timed out data could eventually come in, and end up being seen as the result for a subsequent lookup.\n" .
"- fixed a couple cases in NSAP.php where I was comparing a string to to an integer.\n"
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
