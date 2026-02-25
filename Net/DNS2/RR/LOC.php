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

/**
 * LOC Resource Record - RFC1876 section 2
 *
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *      |        VERSION        |         SIZE          |
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *      |       HORIZ PRE       |       VERT PRE        |
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *      |                   LATITUDE                    |
 *      |                                               |
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *      |                   LONGITUDE                   |
 *      |                                               |
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *      |                   ALTITUDE                    |
 *      |                                               |
 *      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
class Net_DNS2_RR_LOC extends Net_DNS2_RR
{
    public int $version = 0;
    public float $size = 0;
    public float $horiz_pre = 0;
    public float $vert_pre = 0;
    public float $latitude = 0;
    public float $longitude = 0;
    public float $altitude = 0;

    private array $_powerOfTen = [1, 10, 100, 1000, 10000, 100000,
                                  1000000, 10000000, 100000000, 1000000000];

    const CONV_SEC         = 1000;
    const CONV_MIN         = 60000;
    const CONV_DEG         = 3600000;
    const REFERENCE_ALT    = 10000000;
    const REFERENCE_LATLON = 2147483648;

    #[\Override]
    protected function rrToString(): string
    {
        if ($this->version === 0) {
            return $this->_d2Dms($this->latitude, 'LAT') . ' ' .
                $this->_d2Dms($this->longitude, 'LNG') . ' ' .
                sprintf('%.2fm', $this->altitude) . ' ' .
                sprintf('%.2fm', $this->size) . ' ' .
                sprintf('%.2fm', $this->horiz_pre) . ' ' .
                sprintf('%.2fm', $this->vert_pre);
        }

        return '';
    }

    #[\Override]
    protected function rrFromString(array $rdata): bool
    {
        $res = preg_match(
            '/^(\d+) \s+((\d+) \s+)?(([\d.]+) \s+)?(N|S) \s+(\d+) ' .
            '\s+((\d+) \s+)?(([\d.]+) \s+)?(E|W) \s+(-?[\d.]+) m?(\s+ ' .
            '([\d.]+) m?)?(\s+ ([\d.]+) m?)?(\s+ ([\d.]+) m?)?/ix',
            implode(' ', $rdata), $x
        );

        if ($res) {
            $latdeg = $x[1];
            $latmin = (isset($x[3])) ? $x[3] : 0;
            $latsec = (isset($x[5])) ? $x[5] : 0;
            $lathem = strtoupper($x[6]);

            $this->latitude = $this->_dms2d($latdeg, $latmin, $latsec, $lathem);

            $londeg = $x[7];
            $lonmin = (isset($x[9])) ? $x[9] : 0;
            $lonsec = (isset($x[11])) ? $x[11] : 0;
            $lonhem = strtoupper($x[12]);

            $this->longitude = $this->_dms2d($londeg, $lonmin, $lonsec, $lonhem);

            $this->size      = (float)(isset($x[15]) ? $x[15] : 1);
            $this->horiz_pre = (float)(isset($x[17]) ? $x[17] : 10000);
            $this->vert_pre  = (float)(isset($x[19]) ? $x[19] : 10);
            $this->altitude  = (float)$x[13];

            return true;
        }

        return false;
    }

    #[\Override]
    protected function rrSet(Net_DNS2_Packet &$packet): bool
    {
        if ($this->rdlength > 0) {
            $x = unpack(
                'Cver/Csize/Choriz_pre/Cvert_pre/Nlatitude/Nlongitude/Naltitude',
                $this->rdata
            );

            $this->version = $x['ver'];
            if ($this->version === 0) {
                $this->size      = $this->_precsizeNtoA($x['size']);
                $this->horiz_pre = $this->_precsizeNtoA($x['horiz_pre']);
                $this->vert_pre  = $this->_precsizeNtoA($x['vert_pre']);

                if ($x['latitude'] < 0) {
                    $this->latitude = ($x['latitude'] +
                        self::REFERENCE_LATLON) / self::CONV_DEG;
                } else {
                    $this->latitude = ($x['latitude'] -
                        self::REFERENCE_LATLON) / self::CONV_DEG;
                }

                if ($x['longitude'] < 0) {
                    $this->longitude = ($x['longitude'] +
                        self::REFERENCE_LATLON) / self::CONV_DEG;
                } else {
                    $this->longitude = ($x['longitude'] -
                        self::REFERENCE_LATLON) / self::CONV_DEG;
                }

                $this->altitude = ($x['altitude'] - self::REFERENCE_ALT) / 100;

                return true;
            } else {
                return false;
            }
        }

        return false;
    }

    #[\Override]
    protected function rrGet(Net_DNS2_Packet &$packet): ?string
    {
        if ($this->version === 0) {
            $lat = 0;
            $lng = 0;

            if ($this->latitude < 0) {
                $lat = ($this->latitude * self::CONV_DEG) - self::REFERENCE_LATLON;
            } else {
                $lat = ($this->latitude * self::CONV_DEG) + self::REFERENCE_LATLON;
            }

            if ($this->longitude < 0) {
                $lng = ($this->longitude * self::CONV_DEG) - self::REFERENCE_LATLON;
            } else {
                $lng = ($this->longitude * self::CONV_DEG) + self::REFERENCE_LATLON;
            }

            $packet->offset += 16;

            return pack(
                'CCCCNNN',
                $this->version,
                $this->_precsizeAtoN($this->size),
                $this->_precsizeAtoN($this->horiz_pre),
                $this->_precsizeAtoN($this->vert_pre),
                $lat, $lng,
                ($this->altitude * 100) + self::REFERENCE_ALT
            );
        }

        return null;
    }

    private function _precsizeNtoA(int $prec): float
    {
        $mantissa = (($prec >> 4) & 0x0f) % 10;
        $exponent = (($prec >> 0) & 0x0f) % 10;

        return $mantissa * $this->_powerOfTen[$exponent];
    }

    private function _precsizeAtoN(float $prec): int
    {
        $exponent = 0;
        while ($prec >= 10) {
            $prec /= 10;
            ++$exponent;
        }

        return ((int) $prec << 4) | ($exponent & 0x0f);
    }

    private function _dms2d(int|float|string $deg, int|float|string $min, int|float|string $sec, string $hem): float
    {
        $deg = $deg - 0;
        $min = $min - 0;

        $sign = ($hem === 'W' || $hem === 'S') ? -1 : 1;
        return ((($sec / 60 + $min) / 60) + $deg) * $sign;
    }

    private function _d2Dms(float $data, string $latlng): string
    {
        $deg = 0;
        $min = 0;
        $sec = 0;
        $msec = 0;
        $hem = '';

        if ($latlng === 'LAT') {
            $hem = ($data > 0) ? 'N' : 'S';
        } else {
            $hem = ($data > 0) ? 'E' : 'W';
        }

        $data = abs($data);

        $deg = (int) $data;
        $min = (int) (($data - $deg) * 60);
        $sec = (int) (((($data - $deg) * 60) - $min) * 60);
        $msec = round((((((($data - $deg) * 60) - $min) * 60) - $sec) * 1000));

        return sprintf('%d %02d %02d.%03d %s', $deg, $min, $sec, round($msec), $hem);
    }
}
