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
 * @since     1.6.0
 *
 */

namespace NetDNS2;

abstract class Data implements \Stringable
{
    /**
     * internal encoding types
     */
    public const DATA_TYPE_CANON    = 1;
    public const DATA_TYPE_RFC1035  = 2;
    public const DATA_TYPE_RFC2535  = 3;

    /**
     * the encoding type used by this object
     */
    protected int $m_type;

    /**
     * the value stored in this object
     */
    protected string $m_value = '';

    /**
     * an internal hash used for tracking compressed values
     * 
     * @var array<string,int>
     */
    public static array $compressed = [];

    /**
     * create an new intance of the object; this needs 
     *
     * @param int   $_type   encoding type
     * @param mixed $_data   a string or \NetDNS2\Packet object to extract a value from
     * @param int   $_offset an offset value used to seek inside the data provided.
     *
     * @throws \NetDNS2\Exception
     */
    public function __construct(int $_type, mixed $_data = null, ?int &$_offset = null)
    {
        //
        // store the encoding type
        //
        $this->m_type = $_type;

        //
        // parse as a rdata
        //
        if ( (is_null($_data) == false) && (is_null($_offset) == false) && (is_string($_data) == true) )
        {
            $this->decode($_data, $_offset);

        //
        // store from a \NetDNS2\Packet object
        //
        } else if ( (is_null($_data) == false) && (is_null($_offset) == false) && (($_data instanceof \NetDNS2\Packet) == true) )
        {
            $this->decode($_data->rdata, $_offset);

        //
        // assign as a string
        //
        } else if ( (is_null($_data) == false) && (is_string($_data) == true) )
        {
            $this->m_value = trim($_data, '".');

        //
        // copy constructor
        //
        } else if ( (is_null($_data) == false) && ($_data instanceof \NetDNS2\Data) )
        {
            $this->m_type  = $_data->type();
            $this->m_value = $_data->value();
        }
    }

    /**
     * return the internal value in the magic method
     */
    public function __toString(): string
    {
        return $this->value();
    }

    /**
     * the encoding type
     */
    public function type(): int
    {
        return $this->m_type;
    }

    /**
     * return the internal value
     */
    public function value(): string
    {
        return $this->m_value;
    }

    /**
     * return the internal value length
     */
    public function length(): int
    {
        return strlen($this->m_value);
    }

    /**
     * underlying derived classes need to implement an encode & decode function
     */
    abstract public function encode(?int &$_offset = null): string;
    abstract protected function decode(string $_rdata, int &$_offset): void;
    
    /**
     * domain expansion function
     *
     * @param string $_rdata  the text to extract the values from.
     * @param int    $_offset the offset in the text.
     * @param bool   $_escape if we should escape periods in labels (used for mailboxes)
     *
     * @return array<int,string>
     */
    protected function _decode(string $_rdata, int &$_offset, bool $_escape = false): array
    {
        $labels = [];

        while($_offset < strlen($_rdata))
        {
            $length = ord($_rdata[$_offset++]);

            if ($length <= 0)
            {
                return $labels;

            } else if ($length < 0x40)
            {
                $label = substr($_rdata, $_offset, $length);

                //
                // this function supports escaping periods in labels - primarily for mailbox
                //
                if ( ($_escape == true) && (strpos($label, '.') !== false) )
                {
                    $label = preg_replace('/(?<!\\\)\./', '\.', $label);
                }

                $labels[] = $label;
                $_offset += $length;

            } else
            {
                $pointer = (($length & 0x3f) << 8) + ord($_rdata[$_offset++]);

                return array_merge($labels, $this->_decode($_rdata, $pointer, $_escape));
            }
        }

        return $labels;
    }

    /**
     * canonical encoding
     *
     * @param string $_value the value to encode
     */
    public function encode_canonical(string $_value): string
    {
        if (strlen($_value) == 0)
        {
            return pack('C', 0);
        }

        return pack('Ca*x', strlen($_value), $_value);
    }

    /**
     * compressed names defined in RFC 1035
     *
     * @param string $_value  the value to encode
     * @param int    $_offset used to increment the position in the wire output
     *
     * @throws \NetDNS2\Exception
     */
    protected function encode_rfc1035(string $_value, ?int &$_offset = null): string
    {
        if (strlen($_value) == 0)
        {
            $_offset++;
            return pack('C', 0);
        }

        $data = '';

        //
        // use a lookahead to support escaped periods
        //
        $labels = preg_split('/(?<!\\\)\./', $_value);
        if ($labels === false)
        {
            throw new \NetDNS2\Exception('failed to parse local name value.', \NetDNS2\ENUM\Error::PARSE_ERROR);
        }

        while(count($labels) > 0)
        {
            $name = implode('.', $labels);

            if (isset(self::$compressed[$name]) == true)
            {
                return $data . pack('n', 0xC000 | self::$compressed[$name]);    // 0xC000 first two bits as 1 

            } else
            {
                $label = array_shift($labels);

                $data .= pack('Ca*', strlen($label), $label);
                if ($_offset < 0x4000)
                {
                    self::$compressed[$name] = $_offset;
                    $_offset += strlen($label) + 1;
                }
            }
        }

        $_offset++;

        return $data . pack('x');
    }

    /**
     * uncompressed names defined in RFC 2335
     *
     * @param string $_value  the value to encode
     * @param int    $_offset used to increment the position in the wire output
     *
     * @throws \NetDNS2\Exception
     *
     */
    protected function encode_rfc2535(string $_value, int &$_offset): string
    {
        if (strlen($_value) == 0)
        {
            $_offset++;
            return pack('C', 0);
        }

        $data = '';

        //
        // use a lookahead to support escaped periods
        //
        $labels = preg_split('/(?<!\\\)\./', strtolower($_value));
        if ($labels === false)
        {
            throw new \NetDNS2\Exception('failed to parse local name value.', \NetDNS2\ENUM\Error::PARSE_ERROR);
        }

        foreach($labels as $label)
        {
            $data .= pack('Ca*', strlen($label), $label);
        }

        $_offset += strlen($data) + 1;

        return $data . pack('x');
    }
}
