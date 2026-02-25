# Net_DNS2 — Native PHP DNS Resolver and Updater

A pure PHP library for performing DNS queries, dynamic updates, zone transfers, and notifications.

## Features

- **Fast** — most requests are 2–10× faster than the legacy Net_DNS
- **Modern PHP 8.4** — strict types, typed properties, `match` expressions, `#[\Override]`, PSR-4 namespaces
- **Full IPv4 and IPv6 support** — TCP and UDP sockets
- **DNS Resolver** — recursive and iterative queries for 64+ resource record types
- **Dynamic Updater** — add, delete, and prerequisite checks per RFC 2136
- **NOTIFY support** — DNS notifications per RFC 1996
- **DNSSEC** — AD/CD flags, EDNS(0) OPT records, RRSIG, DNSKEY, DS, NSEC/NSEC3 and more
- **Authentication** — TSIG (HMAC-MD5/SHA1/SHA256/SHA512) and SIG(0) signing
- **Caching** — file-based or shared memory (shmop) response cache
- **65 RR types** — A, AAAA, MX, CNAME, SOA, NS, TXT, SRV, CAA, TLSA, SSHFP, LOC, NAPTR, and many more

## Requirements

- PHP ≥ 8.4
- Extensions: `mbstring`, `xml` (dev: `shmop` for shared-memory cache)

## Installation

```bash
composer require pear/net_dns2
```

## Quick Start

```php
use Net\DNS2\Resolver;

$resolver = new Resolver(['nameservers' => ['8.8.8.8']]);

// A record lookup
$response = $resolver->query('example.com', 'A');
foreach ($response->answer as $rr) {
    echo $rr . "\n"; // example.com. 300 IN A 93.184.216.34
}

// MX record lookup
$response = $resolver->query('example.com', 'MX');
foreach ($response->answer as $rr) {
    echo "{$rr->preference} {$rr->exchange}\n";
}
```

### Dynamic DNS Update

```php
use Net\DNS2\Updater;
use Net\DNS2\RR\RR;

$updater = new Updater('example.com', ['nameservers' => ['ns1.example.com']]);
$updater->signTSIG('keyname', 'base64-secret');

$updater->add(RR::fromString('host.example.com. 3600 IN A 10.0.0.1'));
$updater->update();
```

### DNSSEC Query

```php
use Net\DNS2\Resolver;

$resolver = new Resolver(['nameservers' => ['8.8.8.8']]);
$resolver->dnssec = true;

$response = $resolver->query('example.com', 'A');
echo "Authentic Data: " . ($response->header->ad ? 'yes' : 'no') . "\n";
```

### Caching

```php
use Net\DNS2\Resolver;

$resolver = new Resolver([
    'nameservers'      => ['8.8.8.8'],
    'cache_type'       => 'file',           // 'file', 'shared', or 'none'
    'cache_file'       => '/tmp/dns.cache',
    'cache_size'       => 50000,
    'cache_serializer' => 'serialize',       // 'serialize' or 'json'
]);
```

## Project Structure

```
src/                        PSR-4 root (Net\DNS2\)
├── DNS2.php                Base class with socket management
├── Resolver.php            DNS query resolver
├── Updater.php             Dynamic DNS updater (RFC 2136)
├── Notifier.php            DNS NOTIFY (RFC 1996)
├── Lookups.php             Constants, type maps, lookup tables
├── Header.php              DNS packet header (RFC 1035 §4.1.1)
├── Question.php            DNS question section (RFC 1035 §4.1.2)
├── BitMap.php              NSEC/NSEC3 bitmap encoding
├── Socket.php              TCP/UDP stream socket wrapper
├── PrivateKey.php          DNSSEC private key parser
├── Exception.php           Library exception class
├── Packet/
│   ├── Packet.php          Base packet with name compression
│   ├── Request.php         Outgoing query/update packets
│   └── Response.php        Incoming response parser
├── Cache/
│   ├── Cache.php           Abstract cache with TTL management
│   ├── File.php            File-based cache backend
│   └── Shm.php             Shared memory cache backend
└── RR/
    ├── RR.php              Abstract resource record base class
    └── *.php               65 RR type implementations
```

## Testing

```bash
composer install
vendor/bin/phpunit
```

## License

BSD-2-Clause — see [LICENSE](LICENSE) for details.

## Links

- Website: https://netdns2.com/
- Packagist: https://packagist.org/packages/pear/net_dns2
- Issues: https://github.com/mikepultz/netdns2/issues
