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

namespace NetDNS2\Cache;

/**
 * Redis-based (or Valkey) caching for the NetDNS2\Cache class using the PECL redis extension
 *
 */
final class Redis extends \NetDNS2\Cache
{
    /**
     * the local redis object
     */
    private \Redis $m_cache;

    /**           
     * @see \NetDNS2\Cache::__construct()
     */
    public function __construct(array $_options = []) 
    {
        //                 
        // copy over the options
        //
        $this->m_options = $_options;

        //
        // make sure we have at at least one server to connect to
        //
        if ( (isset($this->m_options['host']) == false) || (isset($this->m_options['port']) == false) )
        {
            throw new \NetDNS2\Exception('you must provide a redis server and port to connect to.', \NetDNS2\ENUM\Error::INT_PARSE_ERROR);
        }

        try
        {
            //
            // this function will output warnings about skipping unknown config options, so we added the
            // @ to silence those.
            //
            $this->m_cache = @new \Redis($this->m_options);

            //
            // make sure we use the php serializer so we can push objects in directly
            //
            $this->m_cache->setOption(\Redis::OPT_SERIALIZER, \Redis::SERIALIZER_PHP);

        } catch(\RedisException $e)
        {
            throw new \NetDNS2\Exception(sprintf('redis error: %s', $e->getMessage()), \NetDNS2\ENUM\Error::INT_FAILED_REDIS);
        }
    }

    /**
     * @see \NetDNS2\Cache::get()
     */
    public function get(string $_key): \NetDNS2\Packet\Response|false
    {
        try
        {
            $res = $this->m_cache->get($_key);
            if ($res !== false)
            {
                return $res;
            }

        } catch(\RedisException $e)
        {
            throw new \NetDNS2\Exception(sprintf('redis error: %s', $e->getMessage()), \NetDNS2\ENUM\Error::INT_FAILED_REDIS);
        }

        return false;
    }

    /**
     * @see \NetDNS2\Cache::put()
     */
    public function put(string $_key, \NetDNS2\Packet\Response $_data): void
    {
        //
        // find the TTL
        //
        $ttl = $this->calcuate_ttl($_data);
        try
        {
            $this->m_cache->set($_key, $_data, [ 'ex' => $ttl ]);

        } catch(\RedisException $e)
        {
            throw new \NetDNS2\Exception(sprintf('redis error: %s', $e->getMessage()), \NetDNS2\ENUM\Error::INT_FAILED_REDIS);
        }
    }
}
