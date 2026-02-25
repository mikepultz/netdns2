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

if (!defined('SOCK_STREAM')) {
    define('SOCK_STREAM', 1);
}
if (!defined('SOCK_DGRAM')) {
    define('SOCK_DGRAM', 2);
}

class Net_DNS2_Socket
{
    const SOCK_STREAM = SOCK_STREAM;
    const SOCK_DGRAM  = SOCK_DGRAM;

    /** @var resource|false|null */
    private mixed $sock = null;
    private mixed $context = null;
    private string $local_host = '';
    private int $local_port = 0;

    public string $last_error = '';
    public float $date_created;
    public float $date_last_used = 0.0;

    public function __construct(
        private readonly int $type,
        private readonly string $host,
        private readonly int $port,
        private readonly int $timeout,
    ) {
        $this->date_created = microtime(true);
    }

    public function __destruct()
    {
        $this->close();
    }

    public function bindAddress(string $address, int $port = 0): bool
    {
        $this->local_host = $address;
        $this->local_port = $port;

        return true;
    }

    public function open(): bool
    {
        $opts = ['socket' => []];

        if ($this->local_host !== '') {
            $opts['socket']['bindto'] = $this->local_host;
            if ($this->local_port > 0) {
                $opts['socket']['bindto'] .= ':' . $this->local_port;
            }
        }

        $this->context = @stream_context_create($opts);

        $errno = 0;
        $errstr = '';

        $proto = match ($this->type) {
            self::SOCK_STREAM => 'tcp',
            self::SOCK_DGRAM  => 'udp',
            default           => null,
        };

        if ($proto === null) {
            $this->last_error = "Invalid socket type: {$this->type}";
            return false;
        }

        if (Net_DNS2::isIPv4($this->host)) {
            $target = "{$proto}://{$this->host}:{$this->port}";
        } elseif (Net_DNS2::isIPv6($this->host)) {
            $target = "{$proto}://[{$this->host}]:{$this->port}";
        } else {
            $this->last_error = "invalid address type: {$this->host}";
            return false;
        }

        $this->sock = @stream_socket_client(
            $target, $errno, $errstr, $this->timeout,
            STREAM_CLIENT_CONNECT, $this->context
        );

        if ($this->sock === false) {
            $this->last_error = $errstr;
            return false;
        }

        @stream_set_blocking($this->sock, false);
        @stream_set_timeout($this->sock, $this->timeout);

        return true;
    }

    public function close(): bool
    {
        if (is_resource($this->sock)) {
            @fclose($this->sock);
        }
        return true;
    }

    public function write(string $data): bool
    {
        $length = strlen($data);
        if ($length === 0) {
            $this->last_error = 'empty data on write()';
            return false;
        }

        $read   = null;
        $write  = [$this->sock];
        $except = null;

        $this->date_last_used = microtime(true);

        $result = stream_select($read, $write, $except, $this->timeout);
        if ($result === false) {
            $this->last_error = 'failed on write select()';
            return false;
        }
        if ($result === 0) {
            $this->last_error = 'timeout on write select()';
            return false;
        }

        if ($this->type === self::SOCK_STREAM) {
            $s = chr($length >> 8) . chr($length);
            if (@fwrite($this->sock, $s) === false) {
                $this->last_error = 'failed to fwrite() 16bit length';
                return false;
            }
        }

        $size = @fwrite($this->sock, $data);
        if ($size === false || $size !== $length) {
            $this->last_error = 'failed to fwrite() packet';
            return false;
        }

        return true;
    }

    public function read(int &$size, int $max_size): string|false
    {
        $read   = [$this->sock];
        $write  = null;
        $except = null;

        $this->date_last_used = microtime(true);

        @stream_set_blocking($this->sock, false);

        $result = stream_select($read, $write, $except, $this->timeout);
        if ($result === false) {
            $this->last_error = 'error on read select()';
            return false;
        }
        if ($result === 0) {
            $this->last_error = 'timeout on read select()';
            return false;
        }

        $length = $max_size;

        if ($this->type === self::SOCK_STREAM) {
            $data = fread($this->sock, 2);
            if ($data === false || strlen($data) === 0) {
                $this->last_error = 'failed on fread() for data length';
                return false;
            }

            $length = ord($data[0]) << 8 | ord($data[1]);
            if ($length < Net_DNS2_Lookups::DNS_HEADER_SIZE) {
                return false;
            }
        }

        @stream_set_blocking($this->sock, true);

        $data = '';

        if ($this->type === self::SOCK_STREAM) {
            $chunk_size = $length;

            while (true) {
                $chunk = fread($this->sock, $chunk_size);
                if ($chunk === false) {
                    $this->last_error = 'failed on fread() for data';
                    return false;
                }

                $data .= $chunk;
                $chunk_size -= strlen($chunk);

                if (strlen($data) >= $length) {
                    break;
                }
            }
        } else {
            $data = fread($this->sock, $length);
            if ($data === false) {
                $this->last_error = 'failed on fread() for data';
                return false;
            }
        }

        $size = strlen($data);

        return $data;
    }
}
