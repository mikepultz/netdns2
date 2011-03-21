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
 * @copyright 2011 Mike Pultz <mike@mikepultz.com>
 * @license   http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @version   SVN: $Id:$
 * @link      http://pear.php.net/package/Net_DNS2
 * @since     File available since Release 1.2.0
 */

/**
 * SSL Private Key container class
 *
 * @category Networking
 * @package  Net_DNS2
 * @author   Mike Pultz <mike@mikepultz.com>
 * @license  http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @link     http://pear.php.net/package/Net_DNS2
 * 
 */
class Net_DNS2_PrivateKey
{
    /*
     *
     */
    private $_filename;

    /*
     *
     */
    private $_keytag;

    /*
     *
     */
    private $_signname;

    private $_key_format;

    /*
     *
     */
    private $_algorithm;
   
    private $_prime;
    
    private $_subprime;

    private $_base;

    private $_private_value;

    private $_public_value;

    private $_signature;


    /**
     * Constructor - base constructor the private key container class
     * 
     * @param string private key file to parse and load
     *
     * @access public
     * 
     */
    public function __construct($filename)
    {
        //
        // check for OpenSSL
        //
        if (extension_loaded('openssl') === false) {

            throw new Net_DNS2_Exception(
                'the OpenSSL extension is required to use parse private key.'
            );
        }

        //
        // check to make sure the file exists
        //
        if (is_readable($filename) == false) {

            throw new Net_DNS2_Exception(
                'invalid private key file: ' . $filename
            );
        }

        //
        // get the base filename, and parse it for the local value
        //
        $keyname = basename($filename);
        if (strlen($keyname) == 0) {

            throw new Net_DNS2_Exception(
                'failed to get basename() for: ' . $filename
            );
        }

        //
        // parse the keyname
        //
        if (preg_match("/K(.*)\.\+(\d{3})\+(\d*)\.private/", $keyname, $matches)) {
            
            $this->_signname    = $matches[1];
            $this->_algorithm   = intval($matches[2]);
            $this->_keytag      = intval($matches[3]);

        } else {

            throw new Net_DNS2_Exception(
                'file ' . $keyname . ' does not look like a private key file!'
            );
        }

        //
        // read all the data from the
        //
        $data = file($filename, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES);
        if (count($data) == 0) {
            
            throw new Net_DNS2_Exception(
                'file ' . $keyname . ' is empty!'
            );
        }

        foreach($data as $line) {

            list($key, $value) = explode(':', $line);

            $key    = trim($key);
            $value  = trim($value);

            switch(strtolower($key)) {

            case 'private-key-format':
                $this->_key_format = $value;
                break;

            case 'algorithm':
                if ($this->_algorithm != $value) {
                    throw new Net_DNS2_Exception(
                        'Algorithm mis-match! filename is ' . $this->_algorithm . ', contents say ' . $value
                    );
                }
                break;

            //
            // RSA
            //
            case 'modulus':
                break;

            case 'publicexponent':
                break;

            case 'privateexponent':
                break;
        
            case 'prime1':
                break;

            case 'prime2':
                break;

            case 'exponent1':
                break;

            case 'exponent2':
                break;

            case 'coefficient':
                break;

            //
            // DSA
            //
            case 'prime(p)':
                $this->_prime = $value;
                break;

            case 'subprime(q)':
                $this->_subprime = $value;
                break;

            case 'base(g)':
                $this->_base = $value;
                break;

            case 'private_value(x)':
                $this->_private_value = $value;
                break;

            case 'public_value(y)':
                $this->_public_value = $value;
                break;

            default:
                throw new Net_DNS2_Exception(
                    'unknown private key data: ' . $key . ': ' . $value
                );
            }
        }

        //
        // generate the private key
        //
        switch($this->_algorithm) {
        
        //
        // RSA
        //
        case Net_DNS2_Lookups::DNSSEC_ALGORITHM_RSAMD5:
        case Net_DNS2_Lookups::DNSSEC_ALGORITHM_RSASHA1:
        case Net_DNS2_Lookups::DSNSEC_ALGORITHM_RSASHA1NSEC3SHA1:
        case Net_DNS2_Lookups::DNSSEC_ALGORITHM_RSASHA256:
        case Net_DNS2_Lookups::DNSSEC_ALGORITHM_RSASHA512:



            break;

        //
        // DSA
        //
        case Net_DNS2_Lookups::DNSSEC_ALGORITHM_DSA:
        case Net_DNS2_Lookups::DNSSEC_ALGORITHM_DSANSEC3SHA1:

            $args = array(

                'dsa' => array(

                    'private_key_type'  => OPENSSL_KEYTYPE_DSA,
                    'p'                 => base64_decode($this->_prime),
                    'q'                 => base64_decode($this->_subprime),
                    'g'                 => base64_decode($this->_base),
                    'priv_key'          => base64_decode($this->_private_value),
                    'pub_key'           => base64_decode($this->_public_value)
                )
            );

            //
            // generate and store the key
            //
            $res = openssl_pkey_new($args);
            if ($res === false) {
                throw new Net_DNS2_Exception(openssl_error_string());
            }
            if (openssl_pkey_export($res, $this->_signature) == false) {
                throw new Net_DNS2_Exception(openssl_error_string());
            }

            break;
        
        default:
            throw new Net_DNS2_Exception(
                'we only currently support RSA and DSA encryption.'
            );
        }

        //
        // store the filename incase we need it for something
        //
        $this->_filename = $filename;
    }

    public function filename()
    {
        return $this->_filename;
    }

    public function algorithm()
    {
        return $this->_algorithm;
    }

    public function keytag()
    {
        return $this->_keytag;
    }

    public function signname()
    {
        return $this->_signname;
    }

    public function signature()
    {
        return $this->_signature;
    }    

}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * End:
 */
?>
