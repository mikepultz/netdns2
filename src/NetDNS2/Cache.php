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
 * @since     1.1.0
 *
 */

namespace NetDNS2;

/**
 * A class to provide simple dns lookup caching.
 */
abstract class Cache
{
    /**
     * the filename of the cache file
     */
    protected string $cache_file = '';

    /**
     * the local data store for the cache
     *
     * @var array<string,mixed>
     */
    protected array $cache_data = [];

    /**
     * the size of the cache to use
     */
    protected int $cache_size = 0;

    /**
     * the cache serializer
     */
    protected string $cache_serializer = 'serialize';

    /**
     * an internal flag to make sure we don't load the cache content more than once per instance.
     */ 
    protected bool $cache_opened = false;

    /**
     * open a cache object
     *
     * @param string  $_cache_file path to a file to use for cache storage
     * @param integer $_size       the size of the shared memory segment to create
     * @param string  $_serializer the name of the cache serialize to use
     *
     * @throws \NetDNS2\Exception
     *
     */
    abstract public function open(string $_cache_file, int $_size, string $_serializer): void;

    /**
     * return an instance of a caching object based on the type selected
     *
     * @param string $_type the type name of the caching object to use
     *
     * @throws \NetDNS2\Exception
     *
     */
    public static function factory(string $_type): mixed
    {
        switch(strtolower(trim($_type)))
        {
            case 'shared':
            {
                if (extension_loaded('shmop') == false)
                {
                    throw new \NetDNS2\Exception('shmop library is not available for cache', \NetDNS2\ENUM\Error::CACHE_SHM_UNAVAIL);
                }

                return new \NetDNS2\Cache\Shm;
            }
            case 'file':
            {
                return new \NetDNS2\Cache\File;
            }
            case 'none':
            default:
                ;            
        }

        return null;
    }

    /**
     * returns true/false if the provided key is defined in the cache
     * 
     * @param string $_key the key to lookup in the local cache
     *
     */
    public function has(string $_key): bool
    {
        return (isset($this->cache_data[$_key]) == true) ? true : false;
    }

    /**
     * returns the value for the given key
     * 
     * @param string $_key the key to lookup in the local cache
     *
     * @return mixed returns the cache data on sucess, false on error
     *
     */
    public function get(string $_key): mixed
    {
        if (isset($this->cache_data[$_key]) == true)
        {
            if ($this->cache_serializer == 'json')
            {
                return json_decode($this->cache_data[$_key]['object']);
            } else
            {
                return unserialize($this->cache_data[$_key]['object']);
            }
        }

        return false;
    }

    /**
     * adds a new key/value pair to the cache
     * 
     * @param string $_key  the key for the new cache entry
     * @param mixed  $_data the data to store in cache
     *
     */
    public function put(string $_key, mixed $_data): void
    {
        //
        // default time to live
        //
        $ttl = 86400 * 365;

        //
        // clear the rdata values
        //
        $_data->rdata = '';
        $_data->rdlength = 0;

        //
        // find the lowest TTL, and use that as the TTL for the whole cached object. The downside to using one TTL for the whole object, is that
        // we'll invalidate entries before they actuall expire, causing a real lookup to happen.
        //
        // The upside is that we don't need to require() each RR type in the cache, so we can look at their individual TTL's on each run- we only
        // unserialize the actual RR object when it's get() from the cache.
        //
        foreach($_data->answer as $index => $rr)
        {
            if ($rr->ttl < $ttl)
            {
                $ttl = $rr->ttl;
            }

            $rr->rdata = '';
            $rr->rdlength = 0;
        }
        foreach($_data->authority as $index => $rr)
        {
            $rr->rdata = '';
            $rr->rdlength = 0;
        }
        foreach($_data->additional as $index => $rr)
        {
            $rr->rdata = '';
            $rr->rdlength = 0;
        }

        $this->cache_data[$_key] = [

            'cache_date'    => time(),
            'ttl'           => $ttl
        ];

        if ($this->cache_serializer == 'json')
        {
            $this->cache_data[$_key]['object'] = @json_encode($_data);
            if ($this->cache_data[$_key]['object'] === false)
            {
                unset($this->cache_data[$_key]['object']);
            }

        } else
        {
            $this->cache_data[$_key]['object'] = serialize($_data);
        }
    }

    /**
     * runs a clean up process on the cache data
     *
     */
    protected function clean(): void
    {
        if (count($this->cache_data) > 0)
        {
            //
            // go through each entry and adjust their TTL, and remove entries that 
            // have expired
            //
            $now = time();

            foreach($this->cache_data as $key => $data)
            {
                $diff = $now - $data['cache_date'];

                if ($data['ttl'] <= $diff)
                {
                    unset($this->cache_data[$key]);
                } else
                {
                    $this->cache_data[$key]['ttl'] -= $diff;
                    $this->cache_data[$key]['cache_date'] = $now;
                }
            }
        }
    }

    /**
     * runs a clean up process on the cache data
     *
     */
    protected function resize(): ?string
    {
        if (count($this->cache_data) > 0)
        {
            //
            // serialize the cache data
            //
            if ($this->cache_serializer == 'json')
            {
                $cache = @json_encode($this->cache_data);
                if ($cache === false)
                {
                    return null;
                }

            } else
            {
                $cache = serialize($this->cache_data);
            }

            //
            // only do this part if the size allocated to the cache storage
            // is smaller than the actual cache data
            //
            if (strlen($cache) > $this->cache_size)
            {
                while(strlen($cache) > $this->cache_size)
                {
                    //
                    // go through the data, and remove the entries closed to
                    // their expiration date.
                    //
                    $smallest_ttl = time();
                    $smallest_key = null;

                    foreach($this->cache_data as $key => $data)
                    {
                        if ($data['ttl'] < $smallest_ttl)
                        {
                            $smallest_ttl = $data['ttl'];
                            $smallest_key = $key;
                        }
                    }

                    //
                    // unset the key with the smallest TTL
                    //
                    unset($this->cache_data[$smallest_key]);

                    //
                    // re-serialize
                    //
                    if ($this->cache_serializer == 'json')
                    {
                        $cache = @json_encode($this->cache_data);
                        if ($cache === false)
                        {
                            return null;
                        }

                    } else
                    {
                        $cache = serialize($this->cache_data);
                    }
                }
            }

            if ( ($cache == 'a:0:{}') || ($cache == '{}') )
            {
                return null;
            } else
            {
                return $cache;
            }
        }

        return null;
    }
}
