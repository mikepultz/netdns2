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
$pkg->setAPIVersion('1.2.0');
$pkg->setReleaseVersion('1.2.0');
$pkg->setReleaseStability('stable');
$pkg->setAPIStability('stable');
$pkg->setNotes("- added numeric error codes to the Lookups class, and had each method that throws an exception throw a numeric error code along with the message.\n- dropped all references to InvalidArgumentException; we only use the Net_DNS2_Exception from now on.\n- added the CAA, URI, TALINK, CDS and TA resource records. Some of these are experimental, but are pretty straight forward.\n- fixed a bug in formatString(); my version was only putting double quotes around strings that have spaces, but apparently ALL strings should have double quotes around them. This is how BIND does it.\n- re-organized the Net_DNS2_Lookups initialization code; it no longer creates a global object of itself.\n- fixed a bug in the caching code; in some cases it wouldn't cache the same content more than once.\n- added an option to use JSON to serialize the cache data rather than using the PHP serialize function. JSON is much faster, but loses the class definition, and becomes a stdClass object.\n- fixed a handful of cases where I was using double quotes where a single quote would be fine.");
$pkg->setPackageType('php');
$pkg->addRelease();
$pkg->setPhpDep('5.1.2');
$pkg->setPearinstallerDep('1.4.0a12');
$pkg->addMaintainer('lead', 'mikepultz', 'Mike Pultz', 'mike@mikepultz.com');
$pkg->setLicense('BSD License', 'http://www.opensource.org/licenses/bsd-license.php');
$pkg->generateContents();

$pkg->writePackageFile();

?>
