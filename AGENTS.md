# AGENTS.md

## Cursor Cloud specific instructions

This is **Net_DNS2**, a native PHP DNS Resolver and Updater library (not a web application). There is no server to start or UI to interact with.

### Prerequisites (installed by VM snapshot)

- PHP 8.3 CLI with extensions: xml, mbstring, curl, shmop
- Composer 2.x

### Running tests

```bash
cd /workspace && php -d include_path=".:/workspace" vendor/bin/phpunit --include-path=/workspace tests/
```

The `-d include_path` and `--include-path` flags are required because the test files use `require_once 'Net/DNS2.php'` with a path relative to the workspace root.

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

- The `CacheTest` can occasionally fail on the first run due to transient DNS timeouts, but passes on subsequent runs.
- There is no `phpunit.xml` config file at the project root; tests are run by pointing PHPUnit directly at the `tests/` directory.
- The project uses PSR-0 autoloading (`Net_DNS2` namespace maps to `/workspace/Net/DNS2/`). Composer autoload handles this after `composer install`.
