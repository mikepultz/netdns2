<?php declare(strict_types=1);

namespace Net\DNS2\RR;

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
