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
 * RR bitmap converter for NSEC and NSEC3 records (RFC3845)
 */
class Net_DNS2_BitMap
{
    /**
     * @return array<string>
     */
    public static function bitMapToArray(string $data): array
    {
        if ($data === '') {
            return [];
        }

        $output = [];
        $offset = 0;
        $length = strlen($data);

        while ($offset < $length) {
            $x = unpack("@{$offset}/Cwindow/Clength", $data);
            $offset += 2;

            $bitmap = unpack('C*', substr($data, $offset, $x['length']));
            $offset += $x['length'];

            $bitstr = '';
            foreach ($bitmap as $r) {
                $bitstr .= sprintf('%08b', $r);
            }

            $blen = strlen($bitstr);
            for ($i = 0; $i < $blen; $i++) {
                if ($bitstr[$i] === '1') {
                    $type = $x['window'] * 256 + $i;
                    $output[] = Net_DNS2_Lookups::$rr_types_by_id[$type] ?? ('TYPE' . $type);
                }
            }
        }

        return $output;
    }

    public static function arrayToBitMap(array $data): string
    {
        if (count($data) === 0) {
            return '';
        }

        $max = 0;
        $bm = [];

        foreach ($data as $rr) {
            $rr = strtoupper($rr);

            $type = Net_DNS2_Lookups::$rr_types_by_name[$rr] ?? null;
            if ($type !== null) {
                if (isset(Net_DNS2_Lookups::$rr_qtypes_by_id[$type])
                    || isset(Net_DNS2_Lookups::$rr_metatypes_by_id[$type])
                ) {
                    continue;
                }
            } else {
                [$name, $type] = explode('TYPE', $rr);
                if (!isset($type)) {
                    continue;
                }
            }

            $current_window = (int)($type / 256);
            $val = $type - $current_window * 256.0;
            if ($val > $max) {
                $max = $val;
            }

            $bm[$current_window][$val] = 1;
            $bm[$current_window]['length'] = (int)ceil(($max + 1) / 8);
        }

        $output = '';

        foreach ($bm as $window => $bitdata) {
            $bitstr = '';
            for ($i = 0; $i < $bm[$window]['length'] * 8; $i++) {
                $bitstr .= isset($bm[$window][$i]) ? '1' : '0';
            }

            $output .= pack('CC', $window, $bm[$window]['length']);
            $output .= pack('H*', self::bigBaseConvert($bitstr));
        }

        return $output;
    }

    public static function bigBaseConvert(string $number): string
    {
        $result = '';

        $bin = substr(chunk_split(strrev($number), 4, '-'), 0, -1);
        $temp = preg_split('[-]', $bin, -1, PREG_SPLIT_DELIM_CAPTURE);

        for ($i = count($temp) - 1; $i >= 0; $i--) {
            $result .= base_convert(strrev($temp[$i]), 2, 16);
        }

        return strtoupper($result);
    }
}
