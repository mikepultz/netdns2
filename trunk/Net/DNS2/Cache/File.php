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
 * File-based caching for the Net_DNS2_Cache class
 *
 * @category Networking
 * @package  Net_DNS2
 * @author   Mike Pultz <mike@mikepultz.com>
 * @license  http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link     http://pear.php.net/package/Net_DNS2
 * @see      Net_DNS2_Packet
 *
 */
class Net_DNS2_Cache_File extends Net_DNS2_Cache
{
    /**
     * Constructor
     *
     * @param string $cache_file path to a file to use for cache storage
     *
     * @throws Net_DNS2_Exception
     * @access public
     *
     */
    public function __construct($cache_file)
    {
        $this->cache_file = $cache_file;
        if (file_exists($this->cache_file) == true) {

            //
            // open the file for reading
            //
            $fp = fopen($this->cache_file, "r");
            if ($fp !== false) {
                
                //
                // lock the file just in case
                //
                flock($fp, LOCK_EX);

                //
                // read the file contents
                //
                $this->cache_data = unserialize(
                    fread($fp, filesize($this->cache_file))
                );

                //
                // unlock
                //
                flock($fp, LOCK_UN);

                //
                // close the file
                //
                fclose($fp);

            } else {
                // throw an exception
            }

            $this->clean();
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

            //
            // open the file for writing
            //
            $fp = fopen($this->cache_file, "w");
            if ($fp !== false) {
                
                //
                // lock the file just in case
                //
                flock($fp, LOCK_EX);

                //
                // write the file contents
                //
                fwrite($fp, serialize($this->cache_data));

                //
                // unlock
                //
                flock($fp, LOCK_UN);

                //
                // close the file
                //
                fclose($fp);

            } else {
                // throw an exception
            }
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
