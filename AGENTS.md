# AGENTS.md

## Cursor Cloud specific instructions

This is **Net_DNS2**, a native PHP DNS Resolver and Updater library (not a web application). There is no server to start or UI to interact with. The codebase uses **PSR-4** autoloading with namespace `Net\DNS2\` and PHP 8.4 features.

### Prerequisites (installed by VM snapshot)

- PHP 8.4 CLI with extensions: xml, mbstring, curl, shmop
- Composer 2.x

### Project structure

```
src/                        PSR-4 root (Net\DNS2\)
├── DNS2.php                Base class
├── Resolver.php            DNS query resolver
├── Updater.php             Dynamic DNS updater (RFC 2136)
├── Notifier.php            DNS NOTIFY (RFC 1996)
├── Lookups.php             Constants and lookup tables
├── Packet/                 Packet namespace
│   ├── Packet.php          Base packet class
│   ├── Request.php         Query/update packets
│   └── Response.php        Response parsing
├── Cache/                  Cache namespace
│   ├── Cache.php           Base cache
│   ├── File.php            File-based cache
│   └── Shm.php             Shared memory cache
└── RR/                     Resource Record namespace
    ├── RR.php              Abstract base RR
    ├── A.php, MX.php, ...  64 RR type implementations
```

### Running tests

```bash
vendor/bin/phpunit
```

### Using the library

```php
use Net\DNS2\Resolver;

$r = new Resolver(['nameservers' => ['8.8.8.8']]);
$result = $r->query('example.com', 'A');
foreach ($result->answer as $rr) {
    echo $rr . "\n";
}
```

### Gotchas

- All code uses `declare(strict_types=1)` — be careful with type coercion.
- The `Lookups` class calls `Lookups::init()` at file load time to build reverse lookup tables.
- RR class names in `Lookups::$rr_types_id_to_class` use `::class` constants (e.g., `\Net\DNS2\RR\A::class`).
