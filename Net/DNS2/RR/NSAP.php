<?php declare(strict_types=1);

/**
 * DNS Library for handling lookups and updates.
 *
 * Copyright (c) 2020, Mike Pultz <mike@mikepultz.com>. All rights reserved.
 * See LICENSE for more details.
 */

/**
 * NSAP Resource Record - RFC1706
 *
 *             |--------------|
 *             | <-- IDP -->  |
 *             |--------------|-------------------------------------|
 *             | AFI |  IDI   |            <-- DSP -->              |
 *             |-----|--------|-------------------------------------|
 *             | 47  |  0005  | DFI | AA |Rsvd | RD |Area | ID |Sel |
 *             |-----|--------|-----|----|-----|----|-----|----|----|
 *      octets |  1  |   2    |  1  | 3  |  2  | 2  |  2  | 6  | 1  |
 *             |-----|--------|-----|----|-----|----|-----|----|----|
 */
class Net_DNS2_RR_NSAP extends Net_DNS2_RR
{
    public string $afi = '';
    public string $idi = '';
    public string $dfi = '';
    public string $aa = '';
    public string $rsvd = '';
    public string $rd = '';
    public string $area = '';
    public string $id = '';
    public string $sel = '';

    #[\Override]
    protected function rrToString(): string
    {
        return $this->cleanString($this->afi) . '.' .
            $this->cleanString($this->idi) . '.' .
            $this->cleanString($this->dfi) . '.' .
            $this->cleanString($this->aa) . '.' .
            $this->cleanString($this->rsvd) . '.' .
            $this->cleanString($this->rd) . '.' .
            $this->cleanString($this->area) . '.' .
            $this->cleanString($this->id) . '.' .
            $this->sel;
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $data = strtolower(trim(array_shift($rdata)));

        $data = str_replace(['.', '0x'], '', $data);

        $x = unpack('A2afi/A4idi/A2dfi/A6aa/A4rsvd/A4rd/A4area/A12id/A2sel', $data);

        if ($x['afi'] === '47') {

            $this->afi  = '0x' . $x['afi'];
            $this->idi  = $x['idi'];
            $this->dfi  = $x['dfi'];
            $this->aa   = $x['aa'];
            $this->rsvd = $x['rsvd'];
            $this->rd   = $x['rd'];
            $this->area = $x['area'];
            $this->id   = $x['id'];
            $this->sel  = $x['sel'];

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength === 20) {

            $this->afi = dechex(ord($this->rdata[0]));

            if ($this->afi === '47') {

                $x = unpack(
                    'Cafi/nidi/Cdfi/C3aa/nrsvd/nrd/narea/Nidh/nidl/Csel',
                    $this->rdata
                );

                $this->afi  = sprintf('0x%02x', $x['afi']);
                $this->idi  = sprintf('%04x', $x['idi']);
                $this->dfi  = sprintf('%02x', $x['dfi']);
                $this->aa   = sprintf(
                    '%06x', $x['aa1'] << 16 | $x['aa2'] << 8 | $x['aa3']
                );
                $this->rsvd = sprintf('%04x', $x['rsvd']);
                $this->rd   = sprintf('%04x', $x['rd']);
                $this->area = sprintf('%04x', $x['area']);
                $this->id   = sprintf('%08x', $x['idh']) .
                    sprintf('%04x', $x['idl']);
                $this->sel  = sprintf('%02x', $x['sel']);

                return true;
            }
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if ($this->afi === '0x47') {

            $aa = unpack('A2x/A2y/A2z', $this->aa);
            $id = unpack('A8a/A4b', $this->id);

            $data = pack(
                'CnCCCCnnnNnC',
                hexdec($this->afi),
                hexdec($this->idi),
                hexdec($this->dfi),
                hexdec($aa['x']),
                hexdec($aa['y']),
                hexdec($aa['z']),
                hexdec($this->rsvd),
                hexdec($this->rd),
                hexdec($this->area),
                hexdec($id['a']),
                hexdec($id['b']),
                hexdec($this->sel)
            );

            if (strlen($data) === 20) {

                $packet->offset += 20;
                return $data;
            }
        }

        return null;
    }
}
