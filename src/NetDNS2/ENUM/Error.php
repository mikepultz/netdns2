<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2023, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   NetDNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2025 Mike Pultz <mike@mikepultz.com>
 * @license   https://opensource.org/license/bsd-3-clause/ BSD-3-Clause
 * @link      https://netdns2.com/
 * @since     2.0.0
 *
 */

namespace NetDNS2\ENUM;

enum Error: int
{
    use \NetDNS2\ENUM\Base;

    //
    // error conditions mapped to DNS response codes
    //
    case NONE               = \NetDNS2\ENUM\RR\Code::NOERROR->value;
    case DNS_FORMERR        = \NetDNS2\ENUM\RR\Code::FORMERR->value;
    case DNS_SERVFAIL       = \NetDNS2\ENUM\RR\Code::SERVFAIL->value;
    case DNS_NXDOMAIN       = \NetDNS2\ENUM\RR\Code::NXDOMAIN->value;
    case DNS_NOTIMP         = \NetDNS2\ENUM\RR\Code::NOTIMP->value;
    case DNS_REFUSED        = \NetDNS2\ENUM\RR\Code::REFUSED->value;
    case DNS_YXDOMAIN       = \NetDNS2\ENUM\RR\Code::YXDOMAIN->value;
    case DNS_YXRRSET        = \NetDNS2\ENUM\RR\Code::YXRRSET->value;
    case DNS_NXRRSET        = \NetDNS2\ENUM\RR\Code::NXRRSET->value;
    case DNS_NOTAUTH        = \NetDNS2\ENUM\RR\Code::NOTAUTH->value;
    case DNS_NOTZONE        = \NetDNS2\ENUM\RR\Code::NOTZONE->value;
    case DNS_DSOTYPENI      = \NetDNS2\ENUM\RR\Code::DSOTYPENI->value;

    // 12-15 reserved

    case DNS_BADSIG         = \NetDNS2\ENUM\RR\Code::BADSIG->value;
    case DNS_BADKEY         = \NetDNS2\ENUM\RR\Code::BADKEY->value;
    case DNS_BADTIME        = \NetDNS2\ENUM\RR\Code::BADTIME->value;
    case DNS_BADMODE        = \NetDNS2\ENUM\RR\Code::BADMODE->value;
    case DNS_BADNAME        = \NetDNS2\ENUM\RR\Code::BADNAME->value;
    case DNS_BADALG         = \NetDNS2\ENUM\RR\Code::BADALG->value;
    case DNS_BADTRUNC       = \NetDNS2\ENUM\RR\Code::BADTRUNC->value;    
    case DNS_BADCOOKIE      = \NetDNS2\ENUM\RR\Code::BADCOOKIE->value;

    //
    // other internal error conditions - 3841-4095
    //
    case INT_PARSE_ERROR            = 3841;
    case INT_INVALID_PACKET         = 3842;
    case INT_INVALID_TYPE           = 3843;
    case INT_INVALID_CLASS          = 3844;
    case INT_INVALID_ENUM           = 3845;
    case INT_INVALID_IPV4           = 3846;
    case INT_INVALID_IPV6           = 3847;
    case INT_INVALID_EXTENSION      = 3848;
    case INT_INVALID_ALGORITHM      = 3849;
    case INT_INVALID_NAMESERVER     = 3850;
    case INT_INVALID_SOCKET         = 3851;
    case INT_INVALID_PRIVATE_KEY    = 3852;
    case INT_INVALID_CERTIFICATE    = 3853;

    case INT_FAILED_NAMESERVER      = 3854;
    case INT_FAILED_SOCKET          = 3855;
    case INT_FAILED_SHMOP           = 3856;
    case INT_FAILED_CURL            = 3857;
    case INT_FAILED_OPENSSL         = 3858;
    case INT_FAILED_MEMCACHED       = 3859;
    case INT_FAILED_REDIS           = 3860;

    public function label(): string
    {
        return match($this)
        {
            default => ''
        };
    }
}
