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
 * @copyright 2023 Mike Pultz <mike@mikepultz.com>
 * @license   https://opensource.org/license/bsd-3-clause/ BSD-3-Clause
 * @link      https://netdns2.com/
 * @since     1.2.0
 *
 */

namespace NetDNS2\RR;

/**
 * The CDS RR is implemented exactly like the DS record, so for now we just extend the DS RR and use it.
 *
 * http://www.rfc-editor.org/rfc/rfc7344.txt
 *
 */
final class CDS extends \NetDNS2\RR\DS
{
}
