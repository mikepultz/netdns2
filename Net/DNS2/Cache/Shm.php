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
 * Shared Memory-based caching for the Net_DNS2_Cache class
 *
 * @category Networking
 * @package  Net_DNS2
 * @author   Mike Pultz <mike@mikepultz.com>
 * @license  http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link     http://pear.php.net/package/Net_DNS2
 * @see      Net_DNS2_Packet
 *
 */
class Net_DNS2_Cache_Shm extends Net_DNS2_Cache
{
    /**
     * Constructor
     *
     * @param string  $cache_file path to a file to use for cache storage
     * @param integer $size       the size of the shared memory segment to create
     *
     * @throws Net_DNS2_Exception
     * @access public
     *
     */
    public function __construct($cache_file, $size)
    {
        //
        // make sure the file exists first
        //
        if (!file_exists($cache_file)) {
            touch($cache_file);
        }

        //
        // convert the filename to a IPC key
        //
        $this->cache_file = ftok($cache_file, 't');

        //
        // open the shared memory segment
        //
        $this->cache_id = shmop_open($this->cache_file, 'c', 0644, $size);
        if ($this->cache_id !== false) {

            //
            // this returns the size allocated, and not the size used, but it's
            // still a good check to make sure there's space allocated.
            //
            $size = shmop_size($this->cache_id);
            if ($size > 0) {
            
                //
                // read the data from teh shared memory segment
                //
                $data = shmop_read($this->cache_id, 0, $size);
                if ( ($data !== false) && (strlen($data) > 0) ) {

                    //
                    // unserialize and store the data
                    //
                    $this->cache_data = unserialize($data);

                    //
                    // call clean to clean up old entries
                    //
                    $this->clean();
                }
            }
        } else {

            // throw an exception
        }
    }

    /**
     * Destructor
     *
     * @access public
     *
     */
    public function __destruct()
    {
        if (count($this->cache_data) > 0) {
            
            shmop_write($this->cache_id, serialize($this->cache_data), 0);
        }

        shmop_close($this->cache_id);
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
