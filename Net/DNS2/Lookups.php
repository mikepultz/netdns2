<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   Net_DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 */

Net_DNS2_Lookups::$next_packet_id = mt_rand(0, 65535);

Net_DNS2_Lookups::$rr_types_by_id       = array_flip(Net_DNS2_Lookups::$rr_types_by_name);
Net_DNS2_Lookups::$classes_by_id        = array_flip(Net_DNS2_Lookups::$classes_by_name);
Net_DNS2_Lookups::$rr_types_class_to_id = array_flip(Net_DNS2_Lookups::$rr_types_id_to_class);
Net_DNS2_Lookups::$algorithm_name_to_id = array_flip(Net_DNS2_Lookups::$algorithm_id_to_name);
Net_DNS2_Lookups::$digest_name_to_id    = array_flip(Net_DNS2_Lookups::$digest_id_to_name);
Net_DNS2_Lookups::$rr_qtypes_by_id      = array_flip(Net_DNS2_Lookups::$rr_qtypes_by_name);
Net_DNS2_Lookups::$rr_metatypes_by_id   = array_flip(Net_DNS2_Lookups::$rr_metatypes_by_name);
Net_DNS2_Lookups::$protocol_by_id       = array_flip(Net_DNS2_Lookups::$protocol_by_name);

class Net_DNS2_Lookups
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

    public static int $next_packet_id;

    /** @var array<string, int> */
    public static array $rr_types_by_id = [];

    /** @var array<string, int> */
    public static array $rr_types_by_name = [
        'SIG0'          => 0,
        'A'             => 1,
        'NS'            => 2,
        'MD'            => 3,
        'MF'            => 4,
        'CNAME'         => 5,
        'SOA'           => 6,
        'MB'            => 7,
        'MG'            => 8,
        'MR'            => 9,
        'NULL'          => 10,
        'WKS'           => 11,
        'PTR'           => 12,
        'HINFO'         => 13,
        'MINFO'         => 14,
        'MX'            => 15,
        'TXT'           => 16,
        'RP'            => 17,
        'AFSDB'         => 18,
        'X25'           => 19,
        'ISDN'          => 20,
        'RT'            => 21,
        'NSAP'          => 22,
        'NSAP_PTR'      => 23,
        'SIG'           => 24,
        'KEY'           => 25,
        'PX'            => 26,
        'GPOS'          => 27,
        'AAAA'          => 28,
        'LOC'           => 29,
        'NXT'           => 30,
        'EID'           => 31,
        'NIMLOC'        => 32,
        'SRV'           => 33,
        'ATMA'          => 34,
        'NAPTR'         => 35,
        'KX'            => 36,
        'CERT'          => 37,
        'A6'            => 38,
        'DNAME'         => 39,
        'SINK'          => 40,
        'OPT'           => 41,
        'APL'           => 42,
        'DS'            => 43,
        'SSHFP'         => 44,
        'IPSECKEY'      => 45,
        'RRSIG'         => 46,
        'NSEC'          => 47,
        'DNSKEY'        => 48,
        'DHCID'         => 49,
        'NSEC3'         => 50,
        'NSEC3PARAM'    => 51,
        'TLSA'          => 52,
        'SMIMEA'        => 53,
        'HIP'           => 55,
        'NINFO'         => 56,
        'RKEY'          => 57,
        'TALINK'        => 58,
        'CDS'           => 59,
        'CDNSKEY'       => 60,
        'OPENPGPKEY'    => 61,
        'CSYNC'         => 62,
        'ZONEMD'        => 63,
        'SVCB'          => 64,
        'HTTPS'         => 65,
        'SPF'           => 99,
        'UINFO'         => 100,
        'UID'           => 101,
        'GID'           => 102,
        'UNSPEC'        => 103,
        'NID'           => 104,
        'L32'           => 105,
        'L64'           => 106,
        'LP'            => 107,
        'EUI48'         => 108,
        'EUI64'         => 109,
        'TKEY'          => 249,
        'TSIG'          => 250,
        'IXFR'          => 251,
        'AXFR'          => 252,
        'MAILB'         => 253,
        'MAILA'         => 254,
        'ANY'           => 255,
        'URI'           => 256,
        'CAA'           => 257,
        'AVC'           => 258,
        'DOA'           => 259,
        'AMTRELAY'      => 260,
        'TA'            => 32768,
        'DLV'           => 32769,
        'TYPE65534'     => 65534,
    ];

    /** @var array<int, string> */
    public static array $rr_qtypes_by_id = [];

    /** @var array<string, int> */
    public static array $rr_qtypes_by_name = [
        'IXFR'  => 251,
        'AXFR'  => 252,
        'MAILB' => 253,
        'MAILA' => 254,
        'ANY'   => 255,
    ];

    /** @var array<int, string> */
    public static array $rr_metatypes_by_id = [];

    /** @var array<string, int> */
    public static array $rr_metatypes_by_name = [
        'OPT'  => 41,
        'TKEY' => 249,
        'TSIG' => 250,
    ];

    /** @var array<string, int> */
    public static array $rr_types_class_to_id = [];

    /** @var array<int, string> */
    public static array $rr_types_id_to_class = [
        1       => 'Net_DNS2_RR_A',
        2       => 'Net_DNS2_RR_NS',
        5       => 'Net_DNS2_RR_CNAME',
        6       => 'Net_DNS2_RR_SOA',
        11      => 'Net_DNS2_RR_WKS',
        12      => 'Net_DNS2_RR_PTR',
        13      => 'Net_DNS2_RR_HINFO',
        15      => 'Net_DNS2_RR_MX',
        16      => 'Net_DNS2_RR_TXT',
        17      => 'Net_DNS2_RR_RP',
        18      => 'Net_DNS2_RR_AFSDB',
        19      => 'Net_DNS2_RR_X25',
        20      => 'Net_DNS2_RR_ISDN',
        21      => 'Net_DNS2_RR_RT',
        22      => 'Net_DNS2_RR_NSAP',
        24      => 'Net_DNS2_RR_SIG',
        25      => 'Net_DNS2_RR_KEY',
        26      => 'Net_DNS2_RR_PX',
        28      => 'Net_DNS2_RR_AAAA',
        29      => 'Net_DNS2_RR_LOC',
        31      => 'Net_DNS2_RR_EID',
        32      => 'Net_DNS2_RR_NIMLOC',
        33      => 'Net_DNS2_RR_SRV',
        34      => 'Net_DNS2_RR_ATMA',
        35      => 'Net_DNS2_RR_NAPTR',
        36      => 'Net_DNS2_RR_KX',
        37      => 'Net_DNS2_RR_CERT',
        39      => 'Net_DNS2_RR_DNAME',
        41      => 'Net_DNS2_RR_OPT',
        42      => 'Net_DNS2_RR_APL',
        43      => 'Net_DNS2_RR_DS',
        44      => 'Net_DNS2_RR_SSHFP',
        45      => 'Net_DNS2_RR_IPSECKEY',
        46      => 'Net_DNS2_RR_RRSIG',
        47      => 'Net_DNS2_RR_NSEC',
        48      => 'Net_DNS2_RR_DNSKEY',
        49      => 'Net_DNS2_RR_DHCID',
        50      => 'Net_DNS2_RR_NSEC3',
        51      => 'Net_DNS2_RR_NSEC3PARAM',
        52      => 'Net_DNS2_RR_TLSA',
        53      => 'Net_DNS2_RR_SMIMEA',
        55      => 'Net_DNS2_RR_HIP',
        58      => 'Net_DNS2_RR_TALINK',
        59      => 'Net_DNS2_RR_CDS',
        60      => 'Net_DNS2_RR_CDNSKEY',
        61      => 'Net_DNS2_RR_OPENPGPKEY',
        62      => 'Net_DNS2_RR_CSYNC',
        99      => 'Net_DNS2_RR_SPF',
        104     => 'Net_DNS2_RR_NID',
        105     => 'Net_DNS2_RR_L32',
        106     => 'Net_DNS2_RR_L64',
        107     => 'Net_DNS2_RR_LP',
        108     => 'Net_DNS2_RR_EUI48',
        109     => 'Net_DNS2_RR_EUI64',
        249     => 'Net_DNS2_RR_TKEY',
        250     => 'Net_DNS2_RR_TSIG',
        255     => 'Net_DNS2_RR_ANY',
        256     => 'Net_DNS2_RR_URI',
        257     => 'Net_DNS2_RR_CAA',
        258     => 'Net_DNS2_RR_AVC',
        260     => 'Net_DNS2_RR_AMTRELAY',
        32768   => 'Net_DNS2_RR_TA',
        32769   => 'Net_DNS2_RR_DLV',
        65534   => 'Net_DNS2_RR_TYPE65534',
    ];

    /** @var array<int, string> */
    public static array $classes_by_id = [];

    /** @var array<string, int> */
    public static array $classes_by_name = [
        'IN'   => self::RR_CLASS_IN,
        'CH'   => self::RR_CLASS_CH,
        'HS'   => self::RR_CLASS_HS,
        'NONE' => self::RR_CLASS_NONE,
        'ANY'  => self::RR_CLASS_ANY,
    ];

    /** @var array<int, string> */
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

    /** @var array<string, int> */
    public static array $algorithm_name_to_id = [];

    /** @var array<int, string> */
    public static array $algorithm_id_to_name = [
        self::DNSSEC_ALGORITHM_RES              => 'RES',
        self::DNSSEC_ALGORITHM_RSAMD5           => 'RSAMD5',
        self::DNSSEC_ALGORITHM_DH               => 'DH',
        self::DNSSEC_ALGORITHM_DSA              => 'DSA',
        self::DNSSEC_ALGORITHM_ECC              => 'ECC',
        self::DNSSEC_ALGORITHM_RSASHA1          => 'RSASHA1',
        self::DNSSEC_ALGORITHM_DSANSEC3SHA1     => 'DSA-NSEC3-SHA1',
        self::DSNSEC_ALGORITHM_RSASHA1NSEC3SHA1 => 'RSASHA1-NSEC3-SHA1',
        self::DNSSEC_ALGORITHM_RSASHA256        => 'RSASHA256',
        self::DNSSEC_ALGORITHM_RSASHA512        => 'RSASHA512',
        self::DNSSEC_ALGORITHM_ECCGOST          => 'ECC-GOST',
        self::DNSSEC_ALGORITHM_ECDSAP256SHA256  => 'ECDSAP256SHA256',
        self::DNSSEC_ALGORITHM_ECDSAP384SHA384  => 'ECDSAP384SHA384',
        self::DNSSEC_ALGORITHM_ED25519          => 'ED25519',
        self::DNSSEC_ALGORITHM_ED448            => 'ED448',
        self::DNSSEC_ALGORITHM_INDIRECT         => 'INDIRECT',
        self::DNSSEC_ALGORITHM_PRIVATEDNS       => 'PRIVATEDNS',
        self::DNSSEC_ALGORITHM_PRIVATEOID       => 'PRIVATEOID',
    ];

    /** @var array<string, int> */
    public static array $digest_name_to_id = [];

    /** @var array<int, string> */
    public static array $digest_id_to_name = [
        self::DNSSEC_DIGEST_RES    => 'RES',
        self::DNSSEC_DIGEST_SHA1   => 'SHA-1',
        self::DNSSEC_DIGEST_SHA256 => 'SHA-256',
        self::DNSSEC_DIGEST_GOST   => 'GOST-R-34.11-94',
        self::DNSSEC_DIGEST_SHA384 => 'SHA-384',
    ];

    /** @var array<int, string> */
    public static array $protocol_by_id = [];

    /** @var array<string, int> */
    public static array $protocol_by_name = [
        'ICMP'        => 1,  'IGMP'        => 2,  'GGP'         => 3,
        'ST'          => 5,  'TCP'         => 6,  'UCL'         => 7,
        'EGP'         => 8,  'IGP'         => 9,  'BBN-RCC-MON' => 10,
        'NVP-II'      => 11, 'PUP'         => 12, 'ARGUS'       => 13,
        'EMCON'       => 14, 'XNET'        => 15, 'CHAOS'       => 16,
        'UDP'         => 17, 'MUX'         => 18, 'DCN-MEAS'    => 19,
        'HMP'         => 20, 'PRM'         => 21, 'XNS-IDP'     => 22,
        'TRUNK-1'     => 23, 'TRUNK-2'     => 24, 'LEAF-1'      => 25,
        'LEAF-2'      => 26, 'RDP'         => 27, 'IRTP'        => 28,
        'ISO-TP4'     => 29, 'NETBLT'      => 30, 'MFE-NSP'     => 31,
        'MERIT-INP'   => 32, 'SEP'         => 33, 'CFTP'        => 62,
        'SAT-EXPAK'   => 64, 'MIT-SUBNET'  => 65, 'RVD'         => 66,
        'IPPC'        => 67, 'SAT-MON'     => 69, 'IPCV'        => 71,
        'BR-SAT-MON'  => 76, 'WB-MON'      => 78, 'WB-EXPAK'    => 79,
    ];
}
