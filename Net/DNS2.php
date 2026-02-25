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

spl_autoload_register('Net_DNS2::autoload');

class Net_DNS2
{
    const string VERSION    = '1.5.3';
    const string RESOLV_CONF = '/etc/resolv.conf';

    public bool $use_resolv_options = false;
    public bool $use_tcp = false;
    public int $dns_port = 53;
    public string $local_host = '';
    public int $local_port = 0;
    public int $timeout = 5;
    public bool $ns_random = false;
    public string $domain = '';

    /** @var array<string> */
    public array $search_list = [];

    public string $cache_type = 'none';
    public string $cache_file = '/tmp/net_dns2.cache';
    public int $cache_size = 50000;
    public string $cache_serializer = 'serialize';
    public bool $strict_query_mode = false;
    public bool $recurse = true;
    public bool $dnssec = false;
    public bool $dnssec_ad_flag = false;
    public bool $dnssec_cd_flag = false;
    public int $dnssec_payload_size = 4000;

    public ?Net_DNS2_Exception $last_exception = null;

    /** @var array<string, Net_DNS2_Exception> */
    public array $last_exception_list = [];

    /** @var array<string> */
    public array $nameservers = [];

    /** @var array<int, array<string, Net_DNS2_Socket>> */
    protected array $sock = [Net_DNS2_Socket::SOCK_DGRAM => [], Net_DNS2_Socket::SOCK_STREAM => []];

    protected Net_DNS2_RR_TSIG|Net_DNS2_RR_SIG|null $auth_signature = null;
    protected ?Net_DNS2_Cache $cache = null;
    protected bool $use_cache = false;

    /**
     * @throws Net_DNS2_Exception
     */
    public function __construct(?array $options = null)
    {
        if (!empty($options)) {
            foreach ($options as $key => $value) {
                if ($key === 'nameservers') {
                    $this->setServers($value);
                } else {
                    $this->$key = $value;
                }
            }
        }

        $this->cache = match ($this->cache_type) {
            'shared' => extension_loaded('shmop')
                ? new Net_DNS2_Cache_Shm()
                : throw new Net_DNS2_Exception('shmop library is not available for cache', Net_DNS2_Lookups::E_CACHE_SHM_UNAVAIL),
            'file' => new Net_DNS2_Cache_File(),
            'none' => null,
            default => throw new Net_DNS2_Exception("un-supported cache type: {$this->cache_type}", Net_DNS2_Lookups::E_CACHE_UNSUPPORTED),
        };

        $this->use_cache = $this->cache !== null;
    }

    public static function autoload(string $name): void
    {
        if (str_starts_with($name, 'Net_DNS2')) {
            include str_replace('_', '/', $name) . '.php';
        }
    }

    /**
     * @param array<string>|string $nameservers
     * @throws Net_DNS2_Exception
     */
    public function setServers(array|string $nameservers): bool
    {
        if (is_array($nameservers)) {
            $this->nameservers = $nameservers;
        } else {
            $ns = [];

            if (!is_readable($nameservers)) {
                throw new Net_DNS2_Exception(
                    "resolver file provided is not readable: {$nameservers}",
                    Net_DNS2_Lookups::E_NS_INVALID_FILE
                );
            }

            $data = file_get_contents($nameservers);
            if ($data === false) {
                throw new Net_DNS2_Exception(
                    "failed to read contents of file: {$nameservers}",
                    Net_DNS2_Lookups::E_NS_INVALID_FILE
                );
            }

            foreach (explode("\n", $data) as $line) {
                $line = trim($line);

                if ($line === '' || $line[0] === '#' || $line[0] === ';') {
                    continue;
                }

                if (!str_contains($line, ' ')) {
                    continue;
                }

                [$key, $value] = preg_split('/\s+/', $line, 2);
                $key   = trim(strtolower($key));
                $value = trim(strtolower($value));

                match ($key) {
                    'nameserver' => (self::isIPv4($value) || self::isIPv6($value))
                        ? $ns[] = $value
                        : throw new Net_DNS2_Exception("invalid nameserver entry: {$value}", Net_DNS2_Lookups::E_NS_INVALID_ENTRY),
                    'domain' => $this->domain = $value,
                    'search' => $this->search_list = preg_split('/\s+/', $value),
                    'options' => $this->parseOptions($value),
                    default => null,
                };
            }

            if ($this->domain === '' && count($this->search_list) > 0) {
                $this->domain = $this->search_list[0];
            }

            if (count($ns) > 0) {
                $this->nameservers = $ns;
            }
        }

        $this->nameservers = array_unique($this->nameservers);
        $this->checkServers();

        return true;
    }

    /**
     * @return array<int, array<string, Net_DNS2_Socket>>
     */
    public function getSockets(): array
    {
        return $this->sock;
    }

    public function closeSockets(): bool
    {
        $this->sock[Net_DNS2_Socket::SOCK_DGRAM]  = [];
        $this->sock[Net_DNS2_Socket::SOCK_STREAM] = [];

        return true;
    }

    private function parseOptions(string $value): bool
    {
        if (!$this->use_resolv_options || $value === '') {
            return true;
        }

        foreach (preg_split('/\s+/', strtolower($value)) as $option) {
            if (str_starts_with($option, 'timeout') && str_contains($option, ':')) {
                [, $val] = explode(':', $option);
                if ($val > 0 && $val <= 30) {
                    $this->timeout = (int)$val;
                }
            } elseif (str_starts_with($option, 'rotate')) {
                $this->ns_random = true;
            }
        }

        return true;
    }

    /**
     * @throws Net_DNS2_Exception
     */
    protected function checkServers(string|array|null $default = null): bool
    {
        if (empty($this->nameservers)) {
            if ($default !== null) {
                $this->setServers($default);
            } else {
                throw new Net_DNS2_Exception(
                    'empty name servers list; you must provide a list of name servers, or the path to a resolv.conf file.',
                    Net_DNS2_Lookups::E_NS_INVALID_ENTRY
                );
            }
        }

        return true;
    }

    public function signTSIG(
        Net_DNS2_RR_TSIG|string $keyname,
        string $signature = '',
        string $algorithm = Net_DNS2_RR_TSIG::HMAC_MD5,
    ): bool {
        if ($keyname instanceof Net_DNS2_RR_TSIG) {
            $this->auth_signature = $keyname;
        } else {
            $this->auth_signature = Net_DNS2_RR::fromString(
                strtolower(trim($keyname)) . ' TSIG ' . $signature
            );
            $this->auth_signature->algorithm = $algorithm;
        }

        return true;
    }

    /**
     * @throws Net_DNS2_Exception
     */
    public function signSIG0(Net_DNS2_RR_SIG|string $filename): bool
    {
        if (!extension_loaded('openssl')) {
            throw new Net_DNS2_Exception(
                'the OpenSSL extension is required to use SIG(0).',
                Net_DNS2_Lookups::E_OPENSSL_UNAVAIL
            );
        }

        if ($filename instanceof Net_DNS2_RR_SIG) {
            $this->auth_signature = $filename;
        } else {
            $private = new Net_DNS2_PrivateKey($filename);

            $this->auth_signature = new Net_DNS2_RR_SIG();
            $this->auth_signature->name        = $private->signname;
            $this->auth_signature->ttl         = 0;
            $this->auth_signature->class       = 'ANY';
            $this->auth_signature->algorithm   = $private->algorithm;
            $this->auth_signature->keytag      = $private->keytag;
            $this->auth_signature->signname    = $private->signname;
            $this->auth_signature->typecovered = 'SIG0';
            $this->auth_signature->labels      = 0;
            $this->auth_signature->origttl     = 0;

            $t = time();
            $this->auth_signature->sigincep  = gmdate('YmdHis', $t);
            $this->auth_signature->sigexp    = gmdate('YmdHis', $t + 500);
            $this->auth_signature->private_key = $private;
        }

        match ($this->auth_signature->algorithm) {
            Net_DNS2_Lookups::DNSSEC_ALGORITHM_RSAMD5,
            Net_DNS2_Lookups::DNSSEC_ALGORITHM_RSASHA1,
            Net_DNS2_Lookups::DNSSEC_ALGORITHM_RSASHA256,
            Net_DNS2_Lookups::DNSSEC_ALGORITHM_RSASHA512,
            Net_DNS2_Lookups::DNSSEC_ALGORITHM_DSA => true,
            default => throw new Net_DNS2_Exception(
                'only asymmetric algorithms work with SIG(0)!',
                Net_DNS2_Lookups::E_OPENSSL_INV_ALGO
            ),
        };

        return true;
    }

    public function cacheable(string $type): bool
    {
        return !in_array($type, ['AXFR', 'OPT'], true);
    }

    public static function expandUint32(int $int): int|string
    {
        if ($int < 0 && PHP_INT_MAX === 2147483647) {
            return sprintf('%u', $int);
        }
        return $int;
    }

    public static function isIPv4(string $address): bool
    {
        return filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
    }

    public static function isIPv6(string $address): bool
    {
        return filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    }

    public static function expandIPv6(string $address): string
    {
        $hex = unpack('H*hex', inet_pton($address));
        return substr(preg_replace('/([A-f0-9]{4})/', '$1:', $hex['hex']), 0, -1);
    }

    /**
     * @throws Net_DNS2_Exception
     */
    protected function sendPacket(Net_DNS2_Packet $request, bool $use_tcp): Net_DNS2_Packet_Response
    {
        $data = $request->get();
        if (strlen($data) < Net_DNS2_Lookups::DNS_HEADER_SIZE) {
            throw new Net_DNS2_Exception(
                'invalid or empty packet for sending!',
                Net_DNS2_Lookups::E_PACKET_INVALID,
                null,
                $request
            );
        }

        reset($this->nameservers);

        if ($this->ns_random) {
            shuffle($this->nameservers);
        }

        $response = null;

        while (true) {
            $ns = current($this->nameservers);
            next($this->nameservers);

            if ($ns === false) {
                throw $this->last_exception ?? new Net_DNS2_Exception(
                    'every name server provided has failed',
                    Net_DNS2_Lookups::E_NS_FAILED
                );
            }

            $max_udp_size = $this->dnssec ? $this->dnssec_payload_size : Net_DNS2_Lookups::DNS_MAX_UDP_SIZE;

            if ($use_tcp || strlen($data) > $max_udp_size) {
                try {
                    $response = $this->sendTCPRequest(
                        $ns, $data,
                        $request->question[0]->qtype === 'AXFR'
                    );
                } catch (Net_DNS2_Exception $e) {
                    $this->last_exception = $e;
                    $this->last_exception_list[$ns] = $e;
                    continue;
                }
            } else {
                try {
                    $response = $this->sendUDPRequest($ns, $data);

                    if ($response->header->tc === 1) {
                        $response = $this->sendTCPRequest($ns, $data);
                    }
                } catch (Net_DNS2_Exception $e) {
                    $this->last_exception = $e;
                    $this->last_exception_list[$ns] = $e;
                    continue;
                }
            }

            if ($request->header->id !== $response->header->id) {
                $this->last_exception = new Net_DNS2_Exception(
                    'invalid header: the request and response id do not match.',
                    Net_DNS2_Lookups::E_HEADER_INVALID, null, $request, $response
                );
                $this->last_exception_list[$ns] = $this->last_exception;
                continue;
            }

            if ($response->header->qr !== Net_DNS2_Lookups::QR_RESPONSE) {
                $this->last_exception = new Net_DNS2_Exception(
                    'invalid header: the response provided is not a response packet.',
                    Net_DNS2_Lookups::E_HEADER_INVALID, null, $request, $response
                );
                $this->last_exception_list[$ns] = $this->last_exception;
                continue;
            }

            if ($response->header->rcode !== Net_DNS2_Lookups::RCODE_NOERROR) {
                $this->last_exception = new Net_DNS2_Exception(
                    'DNS request failed: ' . Net_DNS2_Lookups::$result_code_messages[$response->header->rcode],
                    $response->header->rcode, null, $request, $response
                );
                $this->last_exception_list[$ns] = $this->last_exception;
                continue;
            }

            break;
        }

        return $response;
    }

    /**
     * @throws Net_DNS2_Exception
     */
    private function generateError(int $proto, string $ns, int $error): never
    {
        if (!isset($this->sock[$proto][$ns])) {
            throw new Net_DNS2_Exception('invalid socket referenced', Net_DNS2_Lookups::E_NS_INVALID_SOCKET);
        }

        $last_error = $this->sock[$proto][$ns]->last_error;
        unset($this->sock[$proto][$ns]);

        throw new Net_DNS2_Exception($last_error, $error);
    }

    /**
     * @throws Net_DNS2_Exception
     */
    private function sendTCPRequest(string $ns, string $data, bool $axfr = false): Net_DNS2_Packet_Response
    {
        $start_time = microtime(true);

        if (!isset($this->sock[Net_DNS2_Socket::SOCK_STREAM][$ns])
            || !($this->sock[Net_DNS2_Socket::SOCK_STREAM][$ns] instanceof Net_DNS2_Socket)
        ) {
            $this->sock[Net_DNS2_Socket::SOCK_STREAM][$ns] = new Net_DNS2_Socket(
                Net_DNS2_Socket::SOCK_STREAM, $ns, $this->dns_port, $this->timeout
            );

            if ($this->local_host !== '') {
                $this->sock[Net_DNS2_Socket::SOCK_STREAM][$ns]->bindAddress($this->local_host, $this->local_port);
            }

            if (!$this->sock[Net_DNS2_Socket::SOCK_STREAM][$ns]->open()) {
                $this->generateError(Net_DNS2_Socket::SOCK_STREAM, $ns, Net_DNS2_Lookups::E_NS_SOCKET_FAILED);
            }
        }

        if (!$this->sock[Net_DNS2_Socket::SOCK_STREAM][$ns]->write($data)) {
            $this->generateError(Net_DNS2_Socket::SOCK_STREAM, $ns, Net_DNS2_Lookups::E_NS_SOCKET_FAILED);
        }

        $size     = 0;
        $response = null;
        $max_read = $this->dnssec ? $this->dnssec_payload_size : Net_DNS2_Lookups::DNS_MAX_UDP_SIZE;

        if ($axfr) {
            $soa_count = 0;

            while (true) {
                $result = $this->sock[Net_DNS2_Socket::SOCK_STREAM][$ns]->read($size, $max_read);

                if ($result === false || $size < Net_DNS2_Lookups::DNS_HEADER_SIZE) {
                    $this->generateError(Net_DNS2_Socket::SOCK_STREAM, $ns, Net_DNS2_Lookups::E_NS_SOCKET_FAILED);
                }

                $chunk = new Net_DNS2_Packet_Response($result, $size);

                if ($response === null) {
                    $response = clone $chunk;

                    if ($response->header->rcode !== Net_DNS2_Lookups::RCODE_NOERROR) {
                        break;
                    }

                    foreach ($response->answer as $rr) {
                        if ($rr->type === 'SOA') {
                            $soa_count++;
                        }
                    }

                    if ($soa_count >= 2) {
                        break;
                    }
                    continue;
                }

                foreach ($chunk->answer as $rr) {
                    if ($rr->type === 'SOA') {
                        $soa_count++;
                    }
                    $response->answer[] = $rr;
                }

                if ($soa_count >= 2) {
                    break;
                }
            }
        } else {
            $result = $this->sock[Net_DNS2_Socket::SOCK_STREAM][$ns]->read($size, $max_read);

            if ($result === false || $size < Net_DNS2_Lookups::DNS_HEADER_SIZE) {
                $this->generateError(Net_DNS2_Socket::SOCK_STREAM, $ns, Net_DNS2_Lookups::E_NS_SOCKET_FAILED);
            }

            $response = new Net_DNS2_Packet_Response($result, $size);
        }

        $response->response_time      = microtime(true) - $start_time;
        $response->answer_from        = $ns;
        $response->answer_socket_type = Net_DNS2_Socket::SOCK_STREAM;

        return $response;
    }

    /**
     * @throws Net_DNS2_Exception
     */
    private function sendUDPRequest(string $ns, string $data): Net_DNS2_Packet_Response
    {
        $start_time = microtime(true);

        if (!isset($this->sock[Net_DNS2_Socket::SOCK_DGRAM][$ns])
            || !($this->sock[Net_DNS2_Socket::SOCK_DGRAM][$ns] instanceof Net_DNS2_Socket)
        ) {
            $this->sock[Net_DNS2_Socket::SOCK_DGRAM][$ns] = new Net_DNS2_Socket(
                Net_DNS2_Socket::SOCK_DGRAM, $ns, $this->dns_port, $this->timeout
            );

            if ($this->local_host !== '') {
                $this->sock[Net_DNS2_Socket::SOCK_DGRAM][$ns]->bindAddress($this->local_host, $this->local_port);
            }

            if (!$this->sock[Net_DNS2_Socket::SOCK_DGRAM][$ns]->open()) {
                $this->generateError(Net_DNS2_Socket::SOCK_DGRAM, $ns, Net_DNS2_Lookups::E_NS_SOCKET_FAILED);
            }
        }

        if (!$this->sock[Net_DNS2_Socket::SOCK_DGRAM][$ns]->write($data)) {
            $this->generateError(Net_DNS2_Socket::SOCK_DGRAM, $ns, Net_DNS2_Lookups::E_NS_SOCKET_FAILED);
        }

        $size     = 0;
        $max_read = $this->dnssec ? $this->dnssec_payload_size : Net_DNS2_Lookups::DNS_MAX_UDP_SIZE;
        $result   = $this->sock[Net_DNS2_Socket::SOCK_DGRAM][$ns]->read($size, $max_read);

        if ($result === false || $size < Net_DNS2_Lookups::DNS_HEADER_SIZE) {
            $this->generateError(Net_DNS2_Socket::SOCK_DGRAM, $ns, Net_DNS2_Lookups::E_NS_SOCKET_FAILED);
        }

        $response = new Net_DNS2_Packet_Response($result, $size);
        $response->response_time      = microtime(true) - $start_time;
        $response->answer_from        = $ns;
        $response->answer_socket_type = Net_DNS2_Socket::SOCK_DGRAM;

        return $response;
    }
}
