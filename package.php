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
            'package.xml'
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
$pkg->setAPIVersion('1.3.0');
$pkg->setReleaseVersion('1.3.0');
$pkg->setReleaseStability('stable');
$pkg->setAPIStability('stable');
$pkg->setNotes("- re-worked a lot of the code around OPT RR's, including adding support for the DO flag\n- added the AD and CD flags to the Net_DNS2_Header class for DNSSEC\n- added a new function to keep track of RR's that should NOT be cached.\n- added a new flag (dnssec) to request DNSSEC lookups; this adds an OPT RR to the additional section\n- added a new flag (dnssec_payload_size) to adjust the EDNS(0) UDP payload size.\n- added a new flag (dnssec_cd_flag) to set the DNSSEC CD bit to disable signature validation.\n- added a new flag (dnssec_ad_flag) to set the DNSSEC AD bit to request authentic data without needing to set the DO flag.\n- fixed an issue in Net_DNS2_Socket_Sockets; Windows (specifically < 2003) has problems with MSG_WAITALL\n- added a DNSSEC test to the testing suite.");
$pkg->setPackageType('php');
$pkg->addRelease();
$pkg->setPhpDep('5.1.2');
$pkg->setPearinstallerDep('1.4.0a12');
$pkg->addMaintainer('lead', 'mikepultz', 'Mike Pultz', 'mike@mikepultz.com');
$pkg->setLicense('BSD License', 'http://www.opensource.org/licenses/bsd-license.php');
$pkg->generateContents();

$pkg->writePackageFile();

?>
