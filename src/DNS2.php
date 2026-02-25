<?php declare(strict_types=1);

namespace Net\DNS2;

use Net\DNS2\Cache\Cache;
use Net\DNS2\Cache\File;
use Net\DNS2\Cache\Shm;
use Net\DNS2\Packet\Packet;
use Net\DNS2\Packet\Response;
use Net\DNS2\RR\RR;
use Net\DNS2\RR\SIG;
use Net\DNS2\RR\TSIG;

class DNS2
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
    public ?Exception $last_exception = null;
    /** @var array<string, Exception> */
    public array $last_exception_list = [];
    /** @var array<string> */
    public array $nameservers = [];

    /** @var array<int, array<string, Socket>> */
    protected array $sock = [Socket::SOCK_DGRAM => [], Socket::SOCK_STREAM => []];
    protected TSIG|SIG|null $auth_signature = null;
    protected ?Cache $cache = null;
    protected bool $use_cache = false;

    /**
     * @throws Exception
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
                ? new Shm()
                : throw new Exception('shmop library is not available for cache', Lookups::E_CACHE_SHM_UNAVAIL),
            'file'    => new File(),
            'none'    => null,
            default   => throw new Exception("un-supported cache type: {$this->cache_type}", Lookups::E_CACHE_UNSUPPORTED),
        };

        $this->use_cache = $this->cache !== null;
    }

    /**
     * @param array<string>|string $nameservers
     * @throws Exception
     */
    public function setServers(array|string $nameservers): bool
    {
        if (is_array($nameservers)) {
            $this->nameservers = $nameservers;
        } else {
            $ns = [];

            if (!is_readable($nameservers)) {
                throw new Exception("resolver file provided is not readable: {$nameservers}", Lookups::E_NS_INVALID_FILE);
            }

            $data = file_get_contents($nameservers);
            if ($data === false) {
                throw new Exception("failed to read contents of file: {$nameservers}", Lookups::E_NS_INVALID_FILE);
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
                        : throw new Exception("invalid nameserver entry: {$value}", Lookups::E_NS_INVALID_ENTRY),
                    'domain'  => $this->domain = $value,
                    'search'  => $this->search_list = preg_split('/\s+/', $value),
                    'options' => $this->parseOptions($value),
                    default   => null,
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

    /** @return array<int, array<string, Socket>> */
    public function getSockets(): array
    {
        return $this->sock;
    }

    public function closeSockets(): bool
    {
        $this->sock[Socket::SOCK_DGRAM]  = [];
        $this->sock[Socket::SOCK_STREAM] = [];
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

    /** @throws Exception */
    protected function checkServers(string|array|null $default = null): bool
    {
        if (empty($this->nameservers)) {
            if ($default !== null) {
                $this->setServers($default);
            } else {
                throw new Exception(
                    'empty name servers list; you must provide a list of name servers, or the path to a resolv.conf file.',
                    Lookups::E_NS_INVALID_ENTRY
                );
            }
        }
        return true;
    }

    public function signTSIG(TSIG|string $keyname, string $signature = '', string $algorithm = TSIG::HMAC_MD5): bool
    {
        if ($keyname instanceof TSIG) {
            $this->auth_signature = $keyname;
        } else {
            $this->auth_signature = RR::fromString(strtolower(trim($keyname)) . ' TSIG ' . $signature);
            $this->auth_signature->algorithm = $algorithm;
        }
        return true;
    }

    /** @throws Exception */
    public function signSIG0(SIG|string $filename): bool
    {
        if (!extension_loaded('openssl')) {
            throw new Exception('the OpenSSL extension is required to use SIG(0).', Lookups::E_OPENSSL_UNAVAIL);
        }

        if ($filename instanceof SIG) {
            $this->auth_signature = $filename;
        } else {
            $private = new PrivateKey($filename);

            $this->auth_signature = new SIG();
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
            $this->auth_signature->sigincep    = gmdate('YmdHis', $t);
            $this->auth_signature->sigexp      = gmdate('YmdHis', $t + 500);
            $this->auth_signature->private_key = $private;
        }

        match ($this->auth_signature->algorithm) {
            Lookups::DNSSEC_ALGORITHM_RSAMD5,
            Lookups::DNSSEC_ALGORITHM_RSASHA1,
            Lookups::DNSSEC_ALGORITHM_RSASHA256,
            Lookups::DNSSEC_ALGORITHM_RSASHA512,
            Lookups::DNSSEC_ALGORITHM_DSA => true,
            default => throw new Exception('only asymmetric algorithms work with SIG(0)!', Lookups::E_OPENSSL_INV_ALGO),
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

    /** @throws Exception */
    protected function sendPacket(Packet $request, bool $use_tcp): Response
    {
        $data = $request->get();
        if (strlen($data) < Lookups::DNS_HEADER_SIZE) {
            throw new Exception('invalid or empty packet for sending!', Lookups::E_PACKET_INVALID, null, $request);
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
                throw $this->last_exception ?? new Exception('every name server provided has failed', Lookups::E_NS_FAILED);
            }

            $max_udp_size = $this->dnssec ? $this->dnssec_payload_size : Lookups::DNS_MAX_UDP_SIZE;

            if ($use_tcp || strlen($data) > $max_udp_size) {
                try {
                    $response = $this->sendTCPRequest($ns, $data, $request->question[0]->qtype === 'AXFR');
                } catch (Exception $e) {
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
                } catch (Exception $e) {
                    $this->last_exception = $e;
                    $this->last_exception_list[$ns] = $e;
                    continue;
                }
            }

            if ($request->header->id !== $response->header->id) {
                $this->last_exception = new Exception(
                    'invalid header: the request and response id do not match.',
                    Lookups::E_HEADER_INVALID, null, $request, $response
                );
                $this->last_exception_list[$ns] = $this->last_exception;
                continue;
            }

            if ($response->header->qr !== Lookups::QR_RESPONSE) {
                $this->last_exception = new Exception(
                    'invalid header: the response provided is not a response packet.',
                    Lookups::E_HEADER_INVALID, null, $request, $response
                );
                $this->last_exception_list[$ns] = $this->last_exception;
                continue;
            }

            if ($response->header->rcode !== Lookups::RCODE_NOERROR) {
                $this->last_exception = new Exception(
                    'DNS request failed: ' . Lookups::$result_code_messages[$response->header->rcode],
                    $response->header->rcode, null, $request, $response
                );
                $this->last_exception_list[$ns] = $this->last_exception;
                continue;
            }

            break;
        }

        return $response;
    }

    /** @throws Exception */
    private function generateError(int $proto, string $ns, int $error): never
    {
        if (!isset($this->sock[$proto][$ns])) {
            throw new Exception('invalid socket referenced', Lookups::E_NS_INVALID_SOCKET);
        }

        $last_error = $this->sock[$proto][$ns]->last_error;
        unset($this->sock[$proto][$ns]);

        throw new Exception($last_error, $error);
    }

    /** @throws Exception */
    private function sendTCPRequest(string $ns, string $data, bool $axfr = false): Response
    {
        $start_time = microtime(true);

        if (!isset($this->sock[Socket::SOCK_STREAM][$ns])
            || !($this->sock[Socket::SOCK_STREAM][$ns] instanceof Socket)
        ) {
            $this->sock[Socket::SOCK_STREAM][$ns] = new Socket(Socket::SOCK_STREAM, $ns, $this->dns_port, $this->timeout);

            if ($this->local_host !== '') {
                $this->sock[Socket::SOCK_STREAM][$ns]->bindAddress($this->local_host, $this->local_port);
            }
            if (!$this->sock[Socket::SOCK_STREAM][$ns]->open()) {
                $this->generateError(Socket::SOCK_STREAM, $ns, Lookups::E_NS_SOCKET_FAILED);
            }
        }

        if (!$this->sock[Socket::SOCK_STREAM][$ns]->write($data)) {
            $this->generateError(Socket::SOCK_STREAM, $ns, Lookups::E_NS_SOCKET_FAILED);
        }

        $size     = 0;
        $response = null;
        $max_read = $this->dnssec ? $this->dnssec_payload_size : Lookups::DNS_MAX_UDP_SIZE;

        if ($axfr) {
            $soa_count = 0;

            while (true) {
                $result = $this->sock[Socket::SOCK_STREAM][$ns]->read($size, $max_read);

                if ($result === false || $size < Lookups::DNS_HEADER_SIZE) {
                    $this->generateError(Socket::SOCK_STREAM, $ns, Lookups::E_NS_SOCKET_FAILED);
                }

                $chunk = new Response($result, $size);

                if ($response === null) {
                    $response = clone $chunk;

                    if ($response->header->rcode !== Lookups::RCODE_NOERROR) {
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
            $result = $this->sock[Socket::SOCK_STREAM][$ns]->read($size, $max_read);

            if ($result === false || $size < Lookups::DNS_HEADER_SIZE) {
                $this->generateError(Socket::SOCK_STREAM, $ns, Lookups::E_NS_SOCKET_FAILED);
            }

            $response = new Response($result, $size);
        }

        $response->response_time      = microtime(true) - $start_time;
        $response->answer_from        = $ns;
        $response->answer_socket_type = Socket::SOCK_STREAM;

        return $response;
    }

    /** @throws Exception */
    private function sendUDPRequest(string $ns, string $data): Response
    {
        $start_time = microtime(true);

        if (!isset($this->sock[Socket::SOCK_DGRAM][$ns])
            || !($this->sock[Socket::SOCK_DGRAM][$ns] instanceof Socket)
        ) {
            $this->sock[Socket::SOCK_DGRAM][$ns] = new Socket(Socket::SOCK_DGRAM, $ns, $this->dns_port, $this->timeout);

            if ($this->local_host !== '') {
                $this->sock[Socket::SOCK_DGRAM][$ns]->bindAddress($this->local_host, $this->local_port);
            }
            if (!$this->sock[Socket::SOCK_DGRAM][$ns]->open()) {
                $this->generateError(Socket::SOCK_DGRAM, $ns, Lookups::E_NS_SOCKET_FAILED);
            }
        }

        if (!$this->sock[Socket::SOCK_DGRAM][$ns]->write($data)) {
            $this->generateError(Socket::SOCK_DGRAM, $ns, Lookups::E_NS_SOCKET_FAILED);
        }

        $size     = 0;
        $max_read = $this->dnssec ? $this->dnssec_payload_size : Lookups::DNS_MAX_UDP_SIZE;
        $result   = $this->sock[Socket::SOCK_DGRAM][$ns]->read($size, $max_read);

        if ($result === false || $size < Lookups::DNS_HEADER_SIZE) {
            $this->generateError(Socket::SOCK_DGRAM, $ns, Lookups::E_NS_SOCKET_FAILED);
        }

        $response = new Response($result, $size);
        $response->response_time      = microtime(true) - $start_time;
        $response->answer_from        = $ns;
        $response->answer_socket_type = Socket::SOCK_DGRAM;

        return $response;
    }
}
