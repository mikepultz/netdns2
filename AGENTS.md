# AGENTS.md

## Cursor Cloud specific instructions

This is **Net_DNS2**, a native PHP DNS Resolver and Updater library (not a web application). There is no server to start or UI to interact with. The codebase uses PHP 8.4 features (typed constants, `#[\Override]`, `#[\Deprecated]`, `match()`, `str_contains()`/`str_starts_with()`).

### Prerequisites (installed by VM snapshot)

- PHP 8.4 CLI with extensions: xml, mbstring, curl, shmop
- Composer 2.x

### Running tests

```bash
cd /workspace && vendor/bin/phpunit
```

A `phpunit.xml` config at the project root sets up include paths automatically. No extra `-d include_path` flags needed.

### Running the library (hello-world)

Since this is a library (not a service), exercise it directly via PHP CLI:

```bash
php -d include_path=".:/workspace" -r '
require_once "Net/DNS2.php";
$r = new Net_DNS2_Resolver(["nameservers" => ["8.8.8.8"]]);
$result = $r->query("example.com", "A");
foreach ($result->answer as $rr) echo $rr . "\n";
'
```

### Gotchas

- The legacy `Tests_Net_DNS2_CacheTest` can occasionally fail due to the cache file being written on object destruction (after assertions run). New `CacheTest` avoids this issue.
- The project uses PSR-0 autoloading (`Net_DNS2` namespace maps to `/workspace/Net/DNS2/`). Composer autoload handles this after `composer install`.
- All code uses `declare(strict_types=1)` — be careful with type coercion when modifying code.
