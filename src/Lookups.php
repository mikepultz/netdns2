<?php declare(strict_types=1);

namespace Net\DNS2;

use Net\DNS2\RR\RR;
class Lookups
{
    const int DNS_HEADER_SIZE   = 12;
    const int DNS_MAX_UDP_SIZE  = 512;

    const int QR_QUERY          = 0;
    const int QR_RESPONSE       = 1;

    const int OPCODE_QUERY      = 0;
    const int OPCODE_IQUERY     = 1;
    const int OPCODE_STATUS     = 2;
    const int OPCODE_NOTIFY     = 4;
    const int OPCODE_UPDATE     = 5;
    const int OPCODE_DSO        = 6;

    const int RR_CLASS_IN       = 1;
    const int RR_CLASS_CH       = 3;
    const int RR_CLASS_HS       = 4;
    const int RR_CLASS_NONE     = 254;
    const int RR_CLASS_ANY      = 255;

    const int RCODE_NOERROR     = 0;
    const int RCODE_FORMERR     = 1;
    const int RCODE_SERVFAIL    = 2;
    const int RCODE_NXDOMAIN    = 3;
    const int RCODE_NOTIMP      = 4;
    const int RCODE_REFUSED     = 5;
    const int RCODE_YXDOMAIN    = 6;
    const int RCODE_YXRRSET     = 7;
    const int RCODE_NXRRSET     = 8;
    const int RCODE_NOTAUTH     = 9;
    const int RCODE_NOTZONE     = 10;
    const int RCODE_DSOTYPENI   = 11;
    const int RCODE_BADSIG      = 16;
    const int RCODE_BADVERS     = 16;
    const int RCODE_BADKEY      = 17;
    const int RCODE_BADTIME     = 18;
    const int RCODE_BADMODE     = 19;
    const int RCODE_BADNAME     = 20;
    const int RCODE_BADALG      = 21;
    const int RCODE_BADTRUNC    = 22;
    const int RCODE_BADCOOKIE   = 23;

    const int E_NONE                = 0;
    const int E_DNS_FORMERR         = self::RCODE_FORMERR;
    const int E_DNS_SERVFAIL        = self::RCODE_SERVFAIL;
    const int E_DNS_NXDOMAIN        = self::RCODE_NXDOMAIN;
    const int E_DNS_NOTIMP          = self::RCODE_NOTIMP;
    const int E_DNS_REFUSED         = self::RCODE_REFUSED;
    const int E_DNS_YXDOMAIN        = self::RCODE_YXDOMAIN;
    const int E_DNS_YXRRSET         = self::RCODE_YXRRSET;
    const int E_DNS_NXRRSET         = self::RCODE_NXRRSET;
    const int E_DNS_NOTAUTH         = self::RCODE_NOTAUTH;
    const int E_DNS_NOTZONE         = self::RCODE_NOTZONE;
    const int E_DNS_BADSIG          = self::RCODE_BADSIG;
    const int E_DNS_BADKEY          = self::RCODE_BADKEY;
    const int E_DNS_BADTIME         = self::RCODE_BADTIME;
    const int E_DNS_BADMODE         = self::RCODE_BADMODE;
    const int E_DNS_BADNAME         = self::RCODE_BADNAME;
    const int E_DNS_BADALG          = self::RCODE_BADALG;
    const int E_DNS_BADTRUNC        = self::RCODE_BADTRUNC;
    const int E_DNS_BADCOOKIE       = self::RCODE_BADCOOKIE;

    const int E_NS_INVALID_FILE     = 200;
    const int E_NS_INVALID_ENTRY    = 201;
    const int E_NS_FAILED           = 202;
    const int E_NS_SOCKET_FAILED    = 203;
    const int E_NS_INVALID_SOCKET   = 204;

    const int E_PACKET_INVALID      = 300;
    const int E_PARSE_ERROR         = 301;
    const int E_HEADER_INVALID      = 302;
    const int E_QUESTION_INVALID    = 303;
    const int E_RR_INVALID          = 304;

    const int E_OPENSSL_ERROR       = 400;
    const int E_OPENSSL_UNAVAIL     = 401;
    const int E_OPENSSL_INV_PKEY    = 402;
    const int E_OPENSSL_INV_ALGO    = 403;

    const int E_CACHE_UNSUPPORTED   = 500;
    const int E_CACHE_SHM_FILE      = 501;
    const int E_CACHE_SHM_UNAVAIL   = 502;

    const int EDNS0_OPT_LLQ            = 1;
    const int EDNS0_OPT_UL             = 2;
    const int EDNS0_OPT_NSID           = 3;
    const int EDNS0_OPT_DAU            = 5;
    const int EDNS0_OPT_DHU            = 6;
    const int EDNS0_OPT_N3U            = 7;
    const int EDNS0_OPT_CLIENT_SUBNET  = 8;
    const int EDNS0_OPT_EXPIRE         = 9;
    const int EDNS0_OPT_COOKIE         = 10;
    const int EDNS0_OPT_TCP_KEEPALIVE  = 11;
    const int EDNS0_OPT_PADDING        = 12;
    const int EDNS0_OPT_CHAIN          = 13;
    const int EDNS0_OPT_KEY_TAG        = 14;
    const int EDNS0_OPT_CLIENT_TAG     = 16;
    const int EDNS0_OPT_SERVER_TAG     = 17;
    const int EDNS0_OPT_DEVICEID       = 26946;

    const int DNSSEC_ALGORITHM_RES                  = 0;
    const int DNSSEC_ALGORITHM_RSAMD5               = 1;
    const int DNSSEC_ALGORITHM_DH                   = 2;
    const int DNSSEC_ALGORITHM_DSA                  = 3;
    const int DNSSEC_ALGORITHM_ECC                  = 4;
    const int DNSSEC_ALGORITHM_RSASHA1              = 5;
    const int DNSSEC_ALGORITHM_DSANSEC3SHA1         = 6;
    const int DSNSEC_ALGORITHM_RSASHA1NSEC3SHA1     = 7;
    const int DNSSEC_ALGORITHM_RSASHA256            = 8;
    const int DNSSEC_ALGORITHM_RSASHA512            = 10;
    const int DNSSEC_ALGORITHM_ECCGOST              = 12;
    const int DNSSEC_ALGORITHM_ECDSAP256SHA256      = 13;
    const int DNSSEC_ALGORITHM_ECDSAP384SHA384      = 14;
    const int DNSSEC_ALGORITHM_ED25519              = 15;
    const int DNSSEC_ALGORITHM_ED448                = 16;
    const int DNSSEC_ALGORITHM_INDIRECT             = 252;
    const int DNSSEC_ALGORITHM_PRIVATEDNS           = 253;
    const int DNSSEC_ALGORITHM_PRIVATEOID           = 254;

    const int DNSSEC_DIGEST_RES     = 0;
    const int DNSSEC_DIGEST_SHA1    = 1;
    const int DNSSEC_DIGEST_SHA256  = 2;
    const int DNSSEC_DIGEST_GOST    = 3;
    const int DNSSEC_DIGEST_SHA384  = 4;

    public static int $next_packet_id = 0;

    public static array $rr_types_by_id = [];
    public static array $rr_types_by_name = [
        'SIG0' => 0, 'A' => 1, 'NS' => 2, 'MD' => 3, 'MF' => 4,
        'CNAME' => 5, 'SOA' => 6, 'MB' => 7, 'MG' => 8, 'MR' => 9,
        'NULL' => 10, 'WKS' => 11, 'PTR' => 12, 'HINFO' => 13, 'MINFO' => 14,
        'MX' => 15, 'TXT' => 16, 'RP' => 17, 'AFSDB' => 18, 'X25' => 19,
        'ISDN' => 20, 'RT' => 21, 'NSAP' => 22, 'NSAP_PTR' => 23,
        'SIG' => 24, 'KEY' => 25, 'PX' => 26, 'GPOS' => 27, 'AAAA' => 28,
        'LOC' => 29, 'NXT' => 30, 'EID' => 31, 'NIMLOC' => 32, 'SRV' => 33,
        'ATMA' => 34, 'NAPTR' => 35, 'KX' => 36, 'CERT' => 37, 'A6' => 38,
        'DNAME' => 39, 'SINK' => 40, 'OPT' => 41, 'APL' => 42, 'DS' => 43,
        'SSHFP' => 44, 'IPSECKEY' => 45, 'RRSIG' => 46, 'NSEC' => 47,
        'DNSKEY' => 48, 'DHCID' => 49, 'NSEC3' => 50, 'NSEC3PARAM' => 51,
        'TLSA' => 52, 'SMIMEA' => 53, 'HIP' => 55, 'NINFO' => 56,
        'RKEY' => 57, 'TALINK' => 58, 'CDS' => 59, 'CDNSKEY' => 60,
        'OPENPGPKEY' => 61, 'CSYNC' => 62, 'ZONEMD' => 63, 'SVCB' => 64,
        'HTTPS' => 65, 'SPF' => 99, 'UINFO' => 100, 'UID' => 101,
        'GID' => 102, 'UNSPEC' => 103, 'NID' => 104, 'L32' => 105,
        'L64' => 106, 'LP' => 107, 'EUI48' => 108, 'EUI64' => 109,
        'TKEY' => 249, 'TSIG' => 250, 'IXFR' => 251, 'AXFR' => 252,
        'MAILB' => 253, 'MAILA' => 254, 'ANY' => 255, 'URI' => 256,
        'CAA' => 257, 'AVC' => 258, 'DOA' => 259, 'AMTRELAY' => 260,
        'TA' => 32768, 'DLV' => 32769, 'TYPE65534' => 65534,
    ];

    public static array $rr_qtypes_by_id = [];
    public static array $rr_qtypes_by_name = [
        'IXFR' => 251, 'AXFR' => 252, 'MAILB' => 253, 'MAILA' => 254, 'ANY' => 255,
    ];

    public static array $rr_metatypes_by_id = [];
    public static array $rr_metatypes_by_name = [
        'OPT' => 41, 'TKEY' => 249, 'TSIG' => 250,
    ];

    public static array $rr_types_class_to_id = [];
    public static array $rr_types_id_to_class = [
        1 => \Net\DNS2\RR\A::class, 2 => \Net\DNS2\RR\NS::class,
        5 => \Net\DNS2\RR\CNAME::class, 6 => \Net\DNS2\RR\SOA::class,
        11 => \Net\DNS2\RR\WKS::class, 12 => \Net\DNS2\RR\PTR::class,
        13 => \Net\DNS2\RR\HINFO::class, 15 => \Net\DNS2\RR\MX::class,
        16 => \Net\DNS2\RR\TXT::class, 17 => \Net\DNS2\RR\RP::class,
        18 => \Net\DNS2\RR\AFSDB::class, 19 => \Net\DNS2\RR\X25::class,
        20 => \Net\DNS2\RR\ISDN::class, 21 => \Net\DNS2\RR\RT::class,
        22 => \Net\DNS2\RR\NSAP::class, 24 => \Net\DNS2\RR\SIG::class,
        25 => \Net\DNS2\RR\KEY::class, 26 => \Net\DNS2\RR\PX::class,
        28 => \Net\DNS2\RR\AAAA::class, 29 => \Net\DNS2\RR\LOC::class,
        31 => \Net\DNS2\RR\EID::class, 32 => \Net\DNS2\RR\NIMLOC::class,
        33 => \Net\DNS2\RR\SRV::class, 34 => \Net\DNS2\RR\ATMA::class,
        35 => \Net\DNS2\RR\NAPTR::class, 36 => \Net\DNS2\RR\KX::class,
        37 => \Net\DNS2\RR\CERT::class, 39 => \Net\DNS2\RR\DNAME::class,
        41 => \Net\DNS2\RR\OPT::class, 42 => \Net\DNS2\RR\APL::class,
        43 => \Net\DNS2\RR\DS::class, 44 => \Net\DNS2\RR\SSHFP::class,
        45 => \Net\DNS2\RR\IPSECKEY::class, 46 => \Net\DNS2\RR\RRSIG::class,
        47 => \Net\DNS2\RR\NSEC::class, 48 => \Net\DNS2\RR\DNSKEY::class,
        49 => \Net\DNS2\RR\DHCID::class, 50 => \Net\DNS2\RR\NSEC3::class,
        51 => \Net\DNS2\RR\NSEC3PARAM::class, 52 => \Net\DNS2\RR\TLSA::class,
        53 => \Net\DNS2\RR\SMIMEA::class, 55 => \Net\DNS2\RR\HIP::class,
        58 => \Net\DNS2\RR\TALINK::class, 59 => \Net\DNS2\RR\CDS::class,
        60 => \Net\DNS2\RR\CDNSKEY::class, 61 => \Net\DNS2\RR\OPENPGPKEY::class,
        62 => \Net\DNS2\RR\CSYNC::class, 99 => \Net\DNS2\RR\SPF::class,
        104 => \Net\DNS2\RR\NID::class, 105 => \Net\DNS2\RR\L32::class,
        106 => \Net\DNS2\RR\L64::class, 107 => \Net\DNS2\RR\LP::class,
        108 => \Net\DNS2\RR\EUI48::class, 109 => \Net\DNS2\RR\EUI64::class,
        249 => \Net\DNS2\RR\TKEY::class, 250 => \Net\DNS2\RR\TSIG::class,
        255 => \Net\DNS2\RR\ANY::class, 256 => \Net\DNS2\RR\URI::class,
        257 => \Net\DNS2\RR\CAA::class, 258 => \Net\DNS2\RR\AVC::class,
        260 => \Net\DNS2\RR\AMTRELAY::class, 32768 => \Net\DNS2\RR\TA::class,
        32769 => \Net\DNS2\RR\DLV::class, 65534 => \Net\DNS2\RR\TYPE65534::class,
    ];

    public static array $classes_by_id = [];
    public static array $classes_by_name = [
        'IN' => self::RR_CLASS_IN, 'CH' => self::RR_CLASS_CH,
        'HS' => self::RR_CLASS_HS, 'NONE' => self::RR_CLASS_NONE,
        'ANY' => self::RR_CLASS_ANY,
    ];

    public static array $result_code_messages = [
        self::RCODE_NOERROR  => 'The request completed successfully.',
        self::RCODE_FORMERR  => 'The name server was unable to interpret the query.',
        self::RCODE_SERVFAIL => 'The name server was unable to process this query due to a problem with the name server.',
        self::RCODE_NXDOMAIN => 'The domain name referenced in the query does not exist.',
        self::RCODE_NOTIMP   => 'The name server does not support the requested kind of query.',
        self::RCODE_REFUSED  => 'The name server refuses to perform the specified operation for policy reasons.',
        self::RCODE_YXDOMAIN => 'Name Exists when it should not.',
        self::RCODE_YXRRSET  => 'RR Set Exists when it should not.',
        self::RCODE_NXRRSET  => 'RR Set that should exist does not.',
        self::RCODE_NOTAUTH  => 'Server Not Authoritative for zone.',
        self::RCODE_NOTZONE  => 'Name not contained in zone.',
        self::RCODE_BADSIG   => 'TSIG Signature Failure.',
        self::RCODE_BADKEY   => 'Key not recognized.',
        self::RCODE_BADTIME  => 'Signature out of time window.',
        self::RCODE_BADMODE  => 'Bad TKEY Mode.',
        self::RCODE_BADNAME  => 'Duplicate key name.',
        self::RCODE_BADALG   => 'Algorithm not supported.',
        self::RCODE_BADTRUNC => 'Bad truncation.',
    ];

    public static array $algorithm_name_to_id = [];
    public static array $algorithm_id_to_name = [
        self::DNSSEC_ALGORITHM_RES => 'RES', self::DNSSEC_ALGORITHM_RSAMD5 => 'RSAMD5',
        self::DNSSEC_ALGORITHM_DH => 'DH', self::DNSSEC_ALGORITHM_DSA => 'DSA',
        self::DNSSEC_ALGORITHM_ECC => 'ECC', self::DNSSEC_ALGORITHM_RSASHA1 => 'RSASHA1',
        self::DNSSEC_ALGORITHM_DSANSEC3SHA1 => 'DSA-NSEC3-SHA1',
        self::DSNSEC_ALGORITHM_RSASHA1NSEC3SHA1 => 'RSASHA1-NSEC3-SHA1',
        self::DNSSEC_ALGORITHM_RSASHA256 => 'RSASHA256', self::DNSSEC_ALGORITHM_RSASHA512 => 'RSASHA512',
        self::DNSSEC_ALGORITHM_ECCGOST => 'ECC-GOST',
        self::DNSSEC_ALGORITHM_ECDSAP256SHA256 => 'ECDSAP256SHA256',
        self::DNSSEC_ALGORITHM_ECDSAP384SHA384 => 'ECDSAP384SHA384',
        self::DNSSEC_ALGORITHM_ED25519 => 'ED25519', self::DNSSEC_ALGORITHM_ED448 => 'ED448',
        self::DNSSEC_ALGORITHM_INDIRECT => 'INDIRECT', self::DNSSEC_ALGORITHM_PRIVATEDNS => 'PRIVATEDNS',
        self::DNSSEC_ALGORITHM_PRIVATEOID => 'PRIVATEOID',
    ];

    public static array $digest_name_to_id = [];
    public static array $digest_id_to_name = [
        self::DNSSEC_DIGEST_RES => 'RES', self::DNSSEC_DIGEST_SHA1 => 'SHA-1',
        self::DNSSEC_DIGEST_SHA256 => 'SHA-256', self::DNSSEC_DIGEST_GOST => 'GOST-R-34.11-94',
        self::DNSSEC_DIGEST_SHA384 => 'SHA-384',
    ];

    public static array $protocol_by_id = [];
    public static array $protocol_by_name = [
        'ICMP' => 1, 'IGMP' => 2, 'GGP' => 3, 'ST' => 5, 'TCP' => 6,
        'UCL' => 7, 'EGP' => 8, 'IGP' => 9, 'BBN-RCC-MON' => 10,
        'NVP-II' => 11, 'PUP' => 12, 'ARGUS' => 13, 'EMCON' => 14,
        'XNET' => 15, 'CHAOS' => 16, 'UDP' => 17, 'MUX' => 18,
        'DCN-MEAS' => 19, 'HMP' => 20, 'PRM' => 21, 'XNS-IDP' => 22,
        'TRUNK-1' => 23, 'TRUNK-2' => 24, 'LEAF-1' => 25, 'LEAF-2' => 26,
        'RDP' => 27, 'IRTP' => 28, 'ISO-TP4' => 29, 'NETBLT' => 30,
        'MFE-NSP' => 31, 'MERIT-INP' => 32, 'SEP' => 33, 'CFTP' => 62,
        'SAT-EXPAK' => 64, 'MIT-SUBNET' => 65, 'RVD' => 66, 'IPPC' => 67,
        'SAT-MON' => 69, 'IPCV' => 71, 'BR-SAT-MON' => 76, 'WB-MON' => 78,
        'WB-EXPAK' => 79,
    ];

    public static function init(): void
    {
        self::$next_packet_id       = mt_rand(0, 65535);
        self::$rr_types_by_id       = array_flip(self::$rr_types_by_name);
        self::$classes_by_id        = array_flip(self::$classes_by_name);
        self::$rr_types_class_to_id = array_flip(self::$rr_types_id_to_class);
        self::$algorithm_name_to_id = array_flip(self::$algorithm_id_to_name);
        self::$digest_name_to_id    = array_flip(self::$digest_id_to_name);
        self::$rr_qtypes_by_id      = array_flip(self::$rr_qtypes_by_name);
        self::$rr_metatypes_by_id   = array_flip(self::$rr_metatypes_by_name);
        self::$protocol_by_id       = array_flip(self::$protocol_by_name);
    }
}

Lookups::init();
