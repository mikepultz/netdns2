# Local Cache #

Net\_DNS2 includes a built-in local cache to improve query performance. The cache is disabled by default, and can use shared memory, using the PHP [Shmop Extension](http://ca2.php.net/manual/en/book.shmop.php), or a flat file.

The local cache is only used for lookup queries, and is disabled for Updates.

## Shared Memory ##

Net\_DNS2 uses the [Shmop Extension](http://ca2.php.net/manual/en/book.shmop.php). If you do not have the extension installed, and you specify to use the shared memory cache, Net\_DNS2 will throw an exception.

### Example ###

```

$r = new Net_DNS2_Resolver(array(

	'cache_type'	=> 'shared',
	'cache_file'	=> '/tmp/net_dns2.cache',
	'cache_size'	=> 100000
));

```

## Flat File ##

Net\_DNS2 can use a flat file to store the cache information. The **cache\_file** must be in a location PHP can write to, and has enough space to hold a file **cache\_size** bytes big.

### Example ###

```

$r = new Net_DNS2_Resolver(array(

	'cache_type'	=> 'file',
	'cache_file'	=> '/tmp/net_dns2.cache',
	'cache_size'	=> 100000
));

```

## Serialization Method ##

You can also adjust the serialization method used when storing the cache data. By default, Net\_DNS2 uses the PHP serialize()/unserialize(), but you can also use JSON encoding.

JSON encoding is much faster then the PHP serialize functions, but it loses the class information of the objects- everything comes back as stdClass objects.

To change the serialization method, set "cache\_serializer" to either "serialize" or "json".

### Example ###

```

$r = new Net_DNS2_Resolver(array(

	'cache_type'	    => 'file',
	'cache_file'	    => '/tmp/net_dns2.cache',
	'cache_size'	    => 100000,
        'cache_serializer'  => 'json'
));

```

The speed difference is significant.

```

A Query lookup against Google DNS- NO cache
time: 0.0340800285339

	Net_DNS2_RR_A Object
	(
	    [address] => 199.59.148.82
	    [name] => twitter.com
	    [type] => A
	    [class] => IN
	    [ttl] => 28
	    [rdlength] => 4
	    [rdata] => 
	)


with cache + serialize
time: 0.00258994102478

	Net_DNS2_RR_A Object
	(
	    [address] => 199.59.148.82
	    [name] => twitter.com
	    [type] => A
	    [class] => IN
	    [ttl] => 28
	    [rdlength] => 4
	    [rdata] => 
	)


with cache + json
time: 0.00178384780884

	stdClass Object
	(
	    [address] => 199.59.148.82
	    [name] => twitter.com
	    [type] => A
	    [class] => IN
	    [ttl] => 28
	    [rdlength] => 4
	    [rdata] => 
	)


```