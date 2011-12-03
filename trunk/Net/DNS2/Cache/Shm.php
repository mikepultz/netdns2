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
 * @since     File available since Release 1.1.0
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
    /*
     * resource id of the shared memory cache
     */
    private $_cache_id = false;

    /*
     * the IPC key
     */
    private $_cache_file_tok = -1;

    /**
     * open a cache object
     *
     * @param string  $cache_file path to a file to use for cache storage
     * @param integer $size       the size of the shared memory segment to create
     *
     * @throws Net_DNS2_Exception
     * @access public
     * @return void
     *
     */
    public function open($cache_file, $size)
    {
        $this->cache_size = $size;
        $this->cache_file = $cache_file;

        //
        // make sure the file exists first
        //
        if (!file_exists($cache_file)) {

            if (file_put_contents($cache_file, '') === false) {
        
                throw new Net_DNS2_Exception(
                    'failed to create empty SHM file: ' . $cache_file,
                    Net_DNS2_Lookups::E_CACHE_SHM_FILE
                );
            }
        }

        //
        // convert the filename to a IPC key
        //
        $this->_cache_file_tok = ftok($cache_file, 't');
        if ($this->_cache_file_tok == -1) {

            throw new Net_DNS2_Exception(
                'failed on ftok() file: ' . $this->_cache_file_tok,
                Net_DNS2_Lookups::E_CACHE_SHM_FILE
            );
        }

        //
        // try to open an existing cache; if it doesn't exist, then there's no
        // cache, and nothing to do.
        //
        $this->_cache_id = @shmop_open($this->_cache_file_tok, 'w', 0, 0);
        if ($this->_cache_id !== false) {

            //
            // this returns the size allocated, and not the size used, but it's
            // still a good check to make sure there's space allocated.
            //
            $allocated = shmop_size($this->_cache_id);
            if ($allocated > 0) {
            
                //
                // read the data from the shared memory segment
                //
                $data = trim(shmop_read($this->_cache_id, 0, $allocated));
                if ( ($data !== false) && (strlen($data) > 0) ) {

                    //
                    // unserialize and store the data
                    //
                    $this->cache_data = @unserialize($data);

                    //
                    // call clean to clean up old entries
                    //
                    $this->clean();
                }
            }
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
        $fp = fopen($this->cache_file, 'r');
        if ($fp !== false) {

            //
            // lock the file
            //
            flock($fp, LOCK_EX);

            //
            // check to see if we have an open shm segment
            //
            if ($this->_cache_id === false) {

                //
                // try opening it again, incase it was created by another
                // process in the mean time
                //
                $this->_cache_id = @shmop_open(
                    $this->_cache_file_tok, 'w', 0, 0
                );
                if ($this->_cache_id === false) {

                    //
                    // otherwise, create it.
                    //
                    $this->_cache_id = @shmop_open(
                        $this->_cache_file_tok, 'c', 0, $this->cache_size
                    );
                }
            }

            //
            // get the size allocated to the segment
            //
            $allocated = shmop_size($this->_cache_id);

            //
            // read the contents
            //
            $data = trim(shmop_read($this->_cache_id, 0, $allocated));

            //
            // if there was some data
            //    
            if ( ($data !== false) && (strlen($data) > 0) ) {

                //
                // unserialize and store the data
                //
                $this->cache_data = array_merge(
                    $this->cache_data, @unserialize($data)
                );
            }

            //
            // if the size allocated to the segment, is different than 
            // our cache_size setting, then the size changed, and we need to 
            // re-crate it before writing the content.
            //
            if ( ($allocated != $this->cache_size) && ($allocated > 0) ) {

                //
                // delete the segment
                //
                shmop_delete($this->_cache_id);

                //
                // create segment with the new size
                //
                $this->_cache_id = @shmop_open(
                    $this->_cache_file_tok, 'c', 0644, $this->cache_size
                );
                if ($this->_cache_id === false) {

                    //
                    // not much to do here
                    //
                    return;
                }
            }

            //
            // clean up and write the data
            //
            $data = $this->resize();
            if (!is_null($data)) {

                $o = shmop_write($this->_cache_id, $data, 0);
            } else {

                $o = shmop_write($this->_cache_id, '', 0);
            }

            //
            // close the segment
            //
            shmop_close($this->_cache_id);

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
};

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * End:
 */
?>
