<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * DNS Library for handling lookups and updates. 
 *
 * PHP Version 5
 *
 * Copyright (c) 2010, Mike Pultz <mike@mikepultz.com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *   * Neither the name of Mike Pultz nor the names of his contributors 
 *     may be used to endorse or promote products derived from this 
 *     software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRIC
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * @category  Networking
 * @package   Net_DNS2
 * @author    Mike Pultz <mike@mikepultz.com>
 * @copyright 2010 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @version   SVN: $Id$
 * @link      http://pear.php.net/package/Net_DNS2
 * @since     File available since Release 1.0.2
 *
 */

/**
 * A class to provide simple dns lookup caching.
 *
 * @category Networking
 * @package  Net_DNS2
 * @author   Mike Pultz <mike@mikepultz.com>
 * @license  http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link     http://pear.php.net/package/Net_DNS2
 * @see      Net_DNS2_Packet
 *
 */
class Net_DNS2_Cache
{
    /*
     *
     */
    protected $cache_id      = false;

    /*
     *
     */
    protected $cache_file    = "";

    /*
     *
     */
    protected $cache_data    = array();

    /*
     *
     */
    protected $cache_size    = 10000;

    /**
     * returns true/false if the provided key is defined in the cache
     * 
     * @param string $key the key to lookup in the local cache
     *
     * @return boolean
     * @access public
     *
     */
    public function has($key)
    {
        return isset($this->cache_data[$key]);
    }

    /**
     * returns the value for the given key
     * 
     * @param string $key the key to lookup in the local cache
     *
     * @return mixed returns the cache data on sucess, false on error
     * @access public
     *
     */
    public function get($key)
    {
        if (isset($this->cache_data[$key])) {

            return $this->cache_data[$key]['object'];
        } else {

            return false;
        }
    }

    /**
     * adds a new key/value pair to the cache
     * 
     * @param string $key  the key for the new cache entry
     * @param mixed  $data the data to store in cache
     *
     * @return void
     * @access public
     *
     */
    public function put($key, $data)
    {
        $this->cache_data[$key] = array('cache_date' => time(), 'object' => $data);
    }

    /**
     * runs a clean up process on the cache data
     *
     * @return void
     * @access protected
     *
     */
    protected function clean()
    {
        if (count($this->cache_data) > 0) {

            //
            // go through each entry and adjust their TTL, and remove entries that 
            // have expired
            //
            $now = time();
                
            foreach ($this->cache_data as $key => $data) {

                $diff = $now - $data['cache_date'];
            
                $this->cache_data[$key]['cache_date'] = $now;

                foreach ($data['object']->answer as $index => $rr) {
                    
                    if ($rr->ttl <= $diff) {

                        unset($this->cache_data[$key]);
                        break 2;
                    } else {

                        $this->cache_data[$key]['object']->answer[$index]->ttl -= $diff;
                    }
                }
                foreach ($data['object']->authority as $index => $rr) {
                    
                    if ($rr->ttl <= $diff) {

                        unset($this->cache_data[$key]);
                        break 2;
                    } else {

                        $this->cache_data[$key]['object']->authority[$index]->ttl -= $diff;
                    }
                }
                foreach ($data['object']->additional as $index => $rr) {
                    
                    if ($rr->ttl <= $diff) {

                        unset($this->cache_data[$key]);
                        break 2;
                    } else {

                        $this->cache_data[$key]['object']->additional[$index]->ttl -= $diff;
                    }
                }
            }

            //
            // how also check to see if we have too many entries, and remove the
            // oldest entries first
            //
        }
    }
};

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * End:
 */
?>
