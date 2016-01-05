# Net\_DNS2 - Native PHP5 DNS Resolver and Updater #

### The main features for this package include: ###

  * Increased performance; most requests are 2-10x faster than Net\_DNS
  * Near drop-in replacement for Net\_DNS
  * Uses PHP5 style classes and exceptions
  * Support for IPv4 and IPv6, TCP and UDP sockets.
  * Includes a separate, more intuitive "Updater" class for handling dynamic update
  * Support zone signing using TSIG and SIG(0) for updates and zone transfers
  * Includes a local cache using shared memory or flat file to improve performance
  * includes many more RR's, including DNSSEC RR's.


## Installing Net\_DNS2 ##

You can download it directly from PEAR: http://pear.php.net/package/Net_DNS2

```
pear install Net_DNS2
```

Or you can require it directly via Composer: https://packagist.org/packages/pear/net_dns2

```
composer require pear/net_dns2
```

Or download the source above.


## Requirements ##

* PHP 5.1.2+
* The PHP INI setting `mbstring.func_overload` equals 0, 1, 4, or 5.

### Running the test suite ###

If PHPUnit is already installed, use it:

```
$ phpunit tests/AllTests.php
```

Otherwise, install PHPUnit according to its [directions][1] or with Composer:

```
$ curl -sSO getcomposer.org/installer | php
$ composer install
$ vendor/bin/phpunit
```

## Using Net\_DNS2 ##

Using Net_DNS2 is simple:

```
// First, create the resolver
$resolver = new \Net_DNS2_Resolver();

// Then, ask the resolver for resource record sets for any domain:
// Here, the domain is Google and the RR set is the Start Of Authority
try {
    $result = $resolver->query('google.com', 'SOA');
} catch(\Net_DNS2_Exception $ex) {
    die($ex->getMessage());
}

// Finally, iterate over each resource record:
foreach ($result->answer as $answer) {
    // echo out to get a printable dump in zone file format:
    echo $answer . PHP_EOL;

    // or extract specific details with member variables:
    printf(
        '%s %d %s %s %d %d %d %d' . PHP_EOL,
        $answer->name,
        $answer->ttl,
        $answer->class,
        $answer->type,
        $answer->refresh,
        $answer->retry,
        $answer->minimum,
        $answer->expire
    );
}
```

See the Net\_DNS2 Website for more details - https://netdns2.com/

[1]: https://phpunit.de/manual/current/en/installation.html
