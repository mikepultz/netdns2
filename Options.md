# Net\_DNS2 Options #

**nameservers** - _array, defaults to unset_

An array of IP addresses to use as name servers. If this is unset, Net\_DNS2 will default to using the /etc/resolv.conf file.

**use\_tcp** - _boolean, defaults to false._

Tells Net\_DNS2 to use TCP instead of UDP for queries. UDP is faster, but is limited in size. Net\_DNS2 will automatically use TCP for zone transfers (AFXR) and when a response was truncated.

In the event of a truncated response, Net\_DNS2 will switch to TCP, and resend the request.

**dns\_port** - _int, defaults to 53._

The UDP/TCP port to use when making DNS requests.

**local\_host** - _string, defaults to unset._

The local IP address to bind to when making outbound requests.

**local\_port** - _int, defaults to unset._

The local port number to bind to when making outbound requests. **local\_host** can be set without this setting, and the system will auto-allocate the port from the ephemeral ports.

**timeout** - _int, defaults to 5 seconds_

Timeout value to use for socket connections (in seconds)

**ns\_random** - _boolean, defaults to false_

Tells Net\_DNS2 to randomize the name servers list each time it's used.

**domain** - _string, defaults to unset_

The default domain to use for unqualified host names.

**cache\_type** - _string, defaults to 'none'_

Defines the type of cache to use; either 'none' to disable the cache, 'shared' to use the shmop extension, or 'file' to use a flat file.

**cache\_file** - _string, defaults to '/tmp/net\_dns2.cache'_

The file to use for the cache. This is used for both the shared memory and file based cached. Net\_DNS2 will need to write to this file, so it must have proper permissions.

**cache\_size** - _int, defaults to 10000_

The number of bytes Net\_DNS2 is allowed to use as a cache- the bigger the better.

**cache\_serializer** - string, defaults to 'serialize' _(since v1.2.0)_

Defines the serialization method to use when storing the cache content. Can be either 'serialize' to use the PHP serialize function, or 'json' to store the data as a JSON object.

JSON is much faster, but loses the object definition; all content becomes a stdClass object- but all the data is still accessible.

**strict\_query\_mode** - _boolean, defaults to false_

strict\_query\_mode means that if the hostname that was looked up isn't actually in the answer section of the response, Net\_DNS2 will return an empty answer section, instead of an answer section that could contain CNAME records.

**recurse** - _boolean, defaults to true_

if we should set the recursion desired bit to 1 or 0.

**dnssec** - _boolean, defaults to false_

request DNSSEC values, by setting the DO flag to 1; this actually makes the resolver add a OPT RR to the additional section, and sets the DO flag in this RR to 1.

**dnssec\_ad\_flag** - _boolean, defaults to false_

set the DNSSEC AD (Authentic Data) bit on/off.

**dnssec\_cd\_flag** - _boolean, defaults to false_

set the DNSSEC CD (Checking Disabled) bit on/off

**dnssec\_payload\_size** - _integer, defaults to 1280_

the EDNS(0) UDP payload size to use when making DNSSEC requests; see RFC 2671 section 6.2.3 for more details

## Example Usage ##

```

//
// pass the options directly to the constructor
//
$r = new Net_DNS2_Resolver(array(

	'nameservers'	=> array('192.168.0.1', '192.168.0.2'),
	'use_tcp'	=> true,
	'cache_type'	=> 'shared',
	'cache_size'	=> 100000
));

```