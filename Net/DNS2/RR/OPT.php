<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 * See LICENSE for more details.
 */

/**
 * OPT Resource Record - RFC2929 section 3.1
 *
 *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    |                          OPTION-CODE                          |
 *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    |                         OPTION-LENGTH                         |
 *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 *    |                                                               |
 *    /                          OPTION-DATA                          /
 *    /                                                               /
 *    +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 */
class Net_DNS2_RR_OPT extends Net_DNS2_RR
{
    public int $option_code = 0;
    public int $option_length = 0;
    public string $option_data = '';
    public int $extended_rcode = 0;
    public int $version = 0;
    public int $do = 0;
    public int $z = 0;

    public function __construct(?Net_DNS2_Packet &$packet = null, ?array $rr = null)
    {
        $this->type           = 'OPT';
        $this->rdlength       = 0;
        $this->option_length  = 0;
        $this->extended_rcode = 0;
        $this->version        = 0;
        $this->do             = 0;
        $this->z              = 0;

        if ($packet !== null && $rr !== null) {
            parent::__construct($packet, $rr);
        }
    }

    #[\Override]
    protected function rrToString(): string
    {
        return $this->option_code . ' ' . $this->option_data;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $this->option_code   = (int)array_shift($rdata);
        $this->option_data   = array_shift($rdata);
        $this->option_length = strlen($this->option_data);

        $x = unpack('Cextended/Cversion/Cdo/Cz', pack('N', $this->ttl));

        $this->extended_rcode = $x['extended'];
        $this->version        = $x['version'];
        $this->do             = ($x['do'] >> 7);
        $this->z              = $x['z'];

        return true;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        $x = unpack('Cextended/Cversion/Cdo/Cz', pack('N', $this->ttl));

        $this->extended_rcode = $x['extended'];
        $this->version        = $x['version'];
        $this->do             = ($x['do'] >> 7);
        $this->z              = $x['z'];

        if ($this->rdlength > 0) {

            $x = unpack('noption_code/noption_length', $this->rdata);

            $this->option_code   = $x['option_code'];
            $this->option_length = $x['option_length'];

            $this->option_data = substr($this->rdata, 4);
        }

        return true;
    }

    protected function preBuild(): void
    {
        $ttl = unpack(
            'N',
            pack('CCCC', $this->extended_rcode, $this->version, ($this->do << 7), 0)
        );

        $this->ttl = $ttl[1];
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if ($this->option_code) {

            $data = pack('nn', $this->option_code, $this->option_length) .
                $this->option_data;

            $packet->offset += strlen($data);

            return $data;
        }

        return null;
    }
}
