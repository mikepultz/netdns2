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

class Net_DNS2_Cache
{
    protected string $cache_file = '';
    protected array $cache_data = [];
    protected int $cache_size = 0;
    protected string $cache_serializer = 'serialize';
    protected bool $cache_opened = false;

    public function has(string $key): bool
    {
        return isset($this->cache_data[$key]);
    }

    public function get(string $key): mixed
    {
        if (!isset($this->cache_data[$key])) {
            return false;
        }

        return match ($this->cache_serializer) {
            'json'  => json_decode($this->cache_data[$key]['object']),
            default => unserialize($this->cache_data[$key]['object']),
        };
    }

    public function put(string $key, mixed $data): void
    {
        $ttl = 86400 * 365;

        $data->rdata    = '';
        $data->rdlength = 0;

        foreach (['answer', 'authority', 'additional'] as $section) {
            foreach ($data->$section as $rr) {
                if ($rr->ttl < $ttl) {
                    $ttl = $rr->ttl;
                }
                $rr->rdata    = '';
                $rr->rdlength = 0;
            }
        }

        $this->cache_data[$key] = [
            'cache_date' => time(),
            'ttl'        => $ttl,
            'object'     => match ($this->cache_serializer) {
                'json'  => json_encode($data),
                default => serialize($data),
            },
        ];
    }

    protected function clean(): void
    {
        if (count($this->cache_data) === 0) {
            return;
        }

        $now = time();

        foreach ($this->cache_data as $key => $data) {
            $diff = $now - $data['cache_date'];

            if ($data['ttl'] <= $diff) {
                unset($this->cache_data[$key]);
            } else {
                $this->cache_data[$key]['ttl'] -= $diff;
                $this->cache_data[$key]['cache_date'] = $now;
            }
        }
    }

    protected function resize(): ?string
    {
        if (count($this->cache_data) === 0) {
            return null;
        }

        $cache = match ($this->cache_serializer) {
            'json'  => json_encode($this->cache_data),
            default => serialize($this->cache_data),
        };

        if (strlen($cache) > $this->cache_size) {
            while (strlen($cache) > $this->cache_size) {
                $smallest_ttl = time();
                $smallest_key = null;

                foreach ($this->cache_data as $key => $data) {
                    if ($data['ttl'] < $smallest_ttl) {
                        $smallest_ttl = $data['ttl'];
                        $smallest_key = $key;
                    }
                }

                unset($this->cache_data[$smallest_key]);

                $cache = match ($this->cache_serializer) {
                    'json'  => json_encode($this->cache_data),
                    default => serialize($this->cache_data),
                };
            }
        }

        return ($cache === 'a:0:{}' || $cache === '{}') ? null : $cache;
    }
}
