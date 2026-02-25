<?php declare(strict_types=1);

namespace Net\DNS2\RR;

use Net\DNS2\DNS2;
use Net\DNS2\Packet\Packet;

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
 * CAA Resource Record - http://tools.ietf.org/html/draft-ietf-pkix-caa-03
 */
class CAA extends RR
{
    public int $flags = 0;
    public string $tag = '';
    public string $value = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->flags . ' ' . $this->tag . ' "' .
            trim($this->cleanString($this->value), '"') . '"';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->flags    = (int) array_shift($rdata);
        $this->tag      = array_shift($rdata);
        $this->value    = trim($this->cleanString(implode(' ', $rdata)), '"');

        return true;
    }

    #[\Override]
    protected function rrSet(Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack('Cflags/Ctag_length', $this->rdata);

            $this->flags    = $x['flags'];
            $offset         = 2;

            $this->tag      = substr($this->rdata, $offset, $x['tag_length']);
            $offset         += $x['tag_length'];

            $this->value    = substr($this->rdata, $offset);

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Packet &$packet): ?string
    {
        if (strlen($this->value) > 0) {
            $data  = chr($this->flags);
            $data .= chr(strlen($this->tag)) . $this->tag . $this->value;

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
