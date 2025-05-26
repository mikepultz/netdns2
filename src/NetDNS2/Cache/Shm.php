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
 * Shared Memory-based caching for the NetDNS2\Cache class
 *
 */
final class Shm extends \NetDNS2\Cache
{
    /**
     * resource id of the shared memory cache
     */
    private \Shmop $m_cache_id;

    /**
     * the IPC key
     */
    private int $m_cache_file_tok = -1;

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
    public function open(string $_cache_file, int $_size, string $_serializer): void
    {
        $this->cache_file       = $_cache_file;
        $this->cache_size       = $_size;
        $this->cache_serializer = $_serializer;

        //
        // if we've already loaded the cache data, then just return right away
        //
        if ($this->cache_opened == true)
        {
            return;
        }

        //
        // make sure the file exists first
        //
        if (file_exists($this->cache_file) == false)
        {
            if (file_put_contents($this->cache_file, '') === false)
            {
                throw new \NetDNS2\Exception('failed to create empty SHM file: ' . $this->cache_file, \NetDNS2\ENUM\Error::CACHE_SHM_FILE);
            }
        }

        //
        // convert the filename to a IPC key
        //
        $this->m_cache_file_tok = ftok($this->cache_file, 't');
        if ($this->m_cache_file_tok == -1)
        {
            throw new \NetDNS2\Exception('failed on ftok() file: ' . $this->m_cache_file_tok, \NetDNS2\ENUM\Error::CACHE_SHM_FILE);
        }

        //
        // try to open an existing cache; if it doesn't exist, then there's no
        // cache, and nothing to do.
        //
        $cache_id = @shmop_open($this->m_cache_file_tok, 'w', 0, 0);
        if ($cache_id === false)
        {
            throw new \NetDNS2\Exception('failed on shmop_open() file: ' . $this->m_cache_file_tok, \NetDNS2\ENUM\Error::CACHE_SHM_FILE);
        }

        $this->m_cache_id = clone $cache_id;

        //
        // this returns the size allocated, and not the size used, but it's still a good check to make sure there's space allocated.
        //
        $allocated = shmop_size($this->m_cache_id);
        if ($allocated > 0)
        {
            //
            // read the data from the shared memory segment
            //
            $data = trim(shmop_read($this->m_cache_id, 0, $allocated));
            if (strlen($data) > 0)
            {
                //
                // unserialize and store the data
                //
                $decoded = null;

                if ($this->cache_serializer == 'json')
                {
                    try
                    {
                        $decoded = @json_decode(strval($data), true, 512, JSON_THROW_ON_ERROR);

                    } catch(\ValueError $e)
                    {
                        $decoded = null;
                    }

                } else
                {
                    $decoded = unserialize(strval($data));
                }

                if (is_array($decoded) == true)
                {
                    $this->cache_data = $decoded;
                } else
                {
                    $this->cache_data = [];
                }

                //
                // call clean to clean up old entries
                //
                $this->clean();

                //
                // mark the cache as loaded, so we don't load it more than once
                //
                $this->cache_opened = true;
            }
        }
    }

    /**
     * Destructor
     *
     */
    public function __destruct()
    {
        //
        // if there's no cache file set, then there's nothing to do
        //
        if (strlen($this->cache_file) == 0)
        {
            return;
        }

        $fp = fopen($this->cache_file, 'r');
        if ($fp !== false)
        {
            //
            // lock the file
            //
            flock($fp, LOCK_EX);

            //
            // get the size allocated to the segment
            //
            $allocated = shmop_size($this->m_cache_id);

            //
            // read the contents
            //
            $data = trim(shmop_read($this->m_cache_id, 0, $allocated));

            //
            // if there was some data
            //    
            if (strlen($data) > 0)
            {
                //
                // unserialize and store the data
                //
                $c = $this->cache_data;

                $decoded = null;
  
                if ($this->cache_serializer == 'json')
                {
                    try
                    {
                        $decoded = @json_decode(strval($data), true, 512, JSON_THROW_ON_ERROR);

                    } catch(\ValueError $e)
                    {
                        $decoded = null;
                    }

                } else
                {
                    $decoded = unserialize(strval($data));
                }   
                         
                if (is_array($decoded) == true)
                {
                    $this->cache_data = array_merge($c, $decoded);
                }
            }

            //
            // delete the segment
            //
            shmop_delete($this->m_cache_id);

            //
            // clean the data
            //
            $this->clean();

            //
            // clean up and write the data
            //
            $data = $this->resize();

            if (is_null($data) == false)
            {
                //
                // re-create segment
                //
                $cache_id = @shmop_open($this->m_cache_file_tok, 'c', 0644, $this->cache_size);
                if ($cache_id === false)
                {
                    return;
                }

                $this->m_cache_id = clone $cache_id;

                $o = shmop_write($this->m_cache_id, $data, 0);
            }

            //
            // close the segment
            //
            // shmop_close() is deprecated in v8.0.0
            //
            if (version_compare(PHP_VERSION, '8.0.0', '<') == true)
            {
                shmop_close($this->m_cache_id);
            }

            //
            // unlock
            //
            flock($fp, LOCK_UN);

            //
            // close the file
            //
            fclose($fp);
        }
    }
}
