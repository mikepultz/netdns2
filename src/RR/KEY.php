<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\DNS2;

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 *
 * See LICENSE for more details.
 *
 * @category  Networking
 * @package   DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2020 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link      https://netdns2.com/
 */

/**
 * KEY RR - implemented exactly like DNSKEY (extends DNSKEY)
 *
 *     0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
 *   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *   |  A/C  | Z | XT| Z | Z | NAMTYP| Z | Z | Z | Z |      SIG      |
 *   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *
 * DNSKEY only uses bits 7 and 15
 */
class KEY extends DNSKEY
{
}
