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

class Net_DNS2_PrivateKey
{
    public string $filename = '';
    public int $keytag = 0;
    public string $signname = '';
    public int $algorithm = 0;
    public string $key_format = '';
    public \OpenSSLAsymmetricKey|false $instance = false;

    private string $modulus = '';
    private string $public_exponent = '';
    private string $private_exponent = '';
    private string $prime1 = '';
    private string $prime2 = '';
    private string $exponent1 = '';
    private string $exponent2 = '';
    private string $coefficient = '';

    public string $prime = '';
    public string $subprime = '';
    public string $base = '';
    public string $private_value = '';
    public string $public_value = '';

    /**
     * @throws Net_DNS2_Exception
     */
    public function __construct(?string $file = null)
    {
        if ($file !== null) {
            $this->parseFile($file);
        }
    }

    /**
     * @throws Net_DNS2_Exception
     */
    public function parseFile(string $file): bool
    {
        if (!extension_loaded('openssl')) {
            throw new Net_DNS2_Exception(
                'the OpenSSL extension is required to parse private key.',
                Net_DNS2_Lookups::E_OPENSSL_UNAVAIL
            );
        }

        if (!is_readable($file)) {
            throw new Net_DNS2_Exception(
                "invalid private key file: {$file}",
                Net_DNS2_Lookups::E_OPENSSL_INV_PKEY
            );
        }

        $keyname = basename($file);
        if ($keyname === '') {
            throw new Net_DNS2_Exception(
                "failed to get basename() for: {$file}",
                Net_DNS2_Lookups::E_OPENSSL_INV_PKEY
            );
        }

        if (preg_match('/K(.*)\.\+(\d{3})\+(\d*)\.private/', $keyname, $matches)) {
            $this->signname  = $matches[1];
            $this->algorithm = (int)$matches[2];
            $this->keytag    = (int)$matches[3];
        } else {
            throw new Net_DNS2_Exception(
                "file {$keyname} does not look like a private key file!",
                Net_DNS2_Lookups::E_OPENSSL_INV_PKEY
            );
        }

        $data = file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($data === false || count($data) === 0) {
            throw new Net_DNS2_Exception(
                "file {$keyname} is empty!",
                Net_DNS2_Lookups::E_OPENSSL_INV_PKEY
            );
        }

        foreach ($data as $line) {
            [$key, $value] = explode(':', $line);
            $key   = trim($key);
            $value = trim($value);

            match (strtolower($key)) {
                'private-key-format' => $this->key_format = $value,
                'algorithm'          => $this->algorithm !== (int)$value
                    ? throw new Net_DNS2_Exception(
                        "Algorithm mis-match! filename is {$this->algorithm}, contents say {$value}",
                        Net_DNS2_Lookups::E_OPENSSL_INV_ALGO
                    )
                    : null,
                'modulus'           => $this->modulus = $value,
                'publicexponent'    => $this->public_exponent = $value,
                'privateexponent'   => $this->private_exponent = $value,
                'prime1'            => $this->prime1 = $value,
                'prime2'            => $this->prime2 = $value,
                'exponent1'         => $this->exponent1 = $value,
                'exponent2'         => $this->exponent2 = $value,
                'coefficient'       => $this->coefficient = $value,
                'prime(p)'          => $this->prime = $value,
                'subprime(q)'       => $this->subprime = $value,
                'base(g)'           => $this->base = $value,
                'private_value(x)'  => $this->private_value = $value,
                'public_value(y)'   => $this->public_value = $value,
                default             => throw new Net_DNS2_Exception(
                    "unknown private key data: {$key}: {$value}",
                    Net_DNS2_Lookups::E_OPENSSL_INV_PKEY
                ),
            };
        }

        $args = match ($this->algorithm) {
            Net_DNS2_Lookups::DNSSEC_ALGORITHM_RSAMD5,
            Net_DNS2_Lookups::DNSSEC_ALGORITHM_RSASHA1,
            Net_DNS2_Lookups::DNSSEC_ALGORITHM_RSASHA256,
            Net_DNS2_Lookups::DNSSEC_ALGORITHM_RSASHA512 => [
                'rsa' => [
                    'n'    => base64_decode($this->modulus),
                    'e'    => base64_decode($this->public_exponent),
                    'd'    => base64_decode($this->private_exponent),
                    'p'    => base64_decode($this->prime1),
                    'q'    => base64_decode($this->prime2),
                    'dmp1' => base64_decode($this->exponent1),
                    'dmq1' => base64_decode($this->exponent2),
                    'iqmp' => base64_decode($this->coefficient),
                ],
            ],
            Net_DNS2_Lookups::DNSSEC_ALGORITHM_DSA => [
                'dsa' => [
                    'p'        => base64_decode($this->prime),
                    'q'        => base64_decode($this->subprime),
                    'g'        => base64_decode($this->base),
                    'priv_key' => base64_decode($this->private_value),
                    'pub_key'  => base64_decode($this->public_value),
                ],
            ],
            default => throw new Net_DNS2_Exception(
                'we only currently support RSAMD5 and RSASHA1 encryption.',
                Net_DNS2_Lookups::E_OPENSSL_INV_PKEY
            ),
        };

        $this->instance = openssl_pkey_new($args);
        if ($this->instance === false) {
            throw new Net_DNS2_Exception(
                openssl_error_string(),
                Net_DNS2_Lookups::E_OPENSSL_ERROR
            );
        }

        $this->filename = $file;

        return true;
    }
}
