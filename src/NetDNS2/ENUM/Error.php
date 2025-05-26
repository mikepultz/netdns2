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

    case NONE               = \NetDNS2\ENUM\RCode::NOERROR->value;
    case DNS_FORMERR        = \NetDNS2\ENUM\RCode::FORMERR->value;
    case DNS_SERVFAIL       = \NetDNS2\ENUM\RCode::SERVFAIL->value;
    case DNS_NXDOMAIN       = \NetDNS2\ENUM\RCode::NXDOMAIN->value;
    case DNS_NOTIMP         = \NetDNS2\ENUM\RCode::NOTIMP->value;
    case DNS_REFUSED        = \NetDNS2\ENUM\RCode::REFUSED->value;
    case DNS_YXDOMAIN       = \NetDNS2\ENUM\RCode::YXDOMAIN->value;
    case DNS_YXRRSET        = \NetDNS2\ENUM\RCode::YXRRSET->value;
    case DNS_NXRRSET        = \NetDNS2\ENUM\RCode::NXRRSET->value;
    case DNS_NOTAUTH        = \NetDNS2\ENUM\RCode::NOTAUTH->value;
    case DNS_NOTZONE        = \NetDNS2\ENUM\RCode::NOTZONE->value;
    case DNS_DSOTYPENI      = \NetDNS2\ENUM\RCode::DSOTYPENI->value;

    // 12-15 reserved

    case DNS_BADSIG         = \NetDNS2\ENUM\RCode::BADSIG->value;
    case DNS_BADKEY         = \NetDNS2\ENUM\RCode::BADKEY->value;
    case DNS_BADTIME        = \NetDNS2\ENUM\RCode::BADTIME->value;
    case DNS_BADMODE        = \NetDNS2\ENUM\RCode::BADMODE->value;
    case DNS_BADNAME        = \NetDNS2\ENUM\RCode::BADNAME->value;
    case DNS_BADALG         = \NetDNS2\ENUM\RCode::BADALG->value;
    case DNS_BADTRUNC       = \NetDNS2\ENUM\RCode::BADTRUNC->value;    
    case DNS_BADCOOKIE      = \NetDNS2\ENUM\RCode::BADCOOKIE->value;

    // other error conditions

    case NS_INVALID_FILE    = 200;
    case NS_INVALID_ENTRY   = 201;
    case NS_FAILED          = 202;
    case NS_SOCKET_FAILED   = 203;
    case NS_INVALID_SOCKET  = 204;

    case PACKET_INVALID     = 300;
    case PARSE_ERROR        = 301;
    case HEADER_INVALID     = 302;
    case QUESTION_INVALID   = 303;
    case RR_INVALID         = 304;
    case TCP_REQUIRED       = 305;
    case CLASS_INVALID      = 306;

    case OPENSSL_ERROR      = 400;
    case OPENSSL_UNAVAIL    = 401;
    case OPENSSL_INV_PKEY   = 402;
    case OPENSSL_INV_ALGO   = 403;

    case CACHE_UNSUPPORTED  = 500;
    case CACHE_SHM_FILE     = 501;
    case CACHE_SHM_UNAVAIL  = 502;

    case CURL_ERROR         = 600;
    case CURL_UNAVAIL       = 601;

    public function label(): string
    {
        return match($this)
        {
            default => ''
        };
    }
}
