<?php

require_once 'Net/DNS2.php';

class Net_DNS2_ParserTest extends PHPUnit_Framework_TestCase
{
	public function testParser()
	{
		$rrs = array(

			'A'			=> 'example.com. 300 IN A 172.168.0.50',
			'NS'		=> 'example.com. 300 IN NS ns1.mrdns.com.',
			'CNAME'		=> 'example.com. 300 IN CNAME www.example.com.',
			'SOA'		=> 'example.com. 300 IN SOA ns1.mrdns.com. help.mrhost.ca. 1278700841 900 1800 86400 21400',
			'PTR'		=> '26.in-addr.arpa. 300 IN PTR example.com.',
			'HINFO'		=> 'example.com. 300 IN HINFO PC-Intel-700mhz "Redhat \"Linux\" 7.1"',
			'MX'		=> 'example.com. 300 IN MX 10 mx1.mrhost.ca.',
			'TXT'		=> 'example.com. 300 IN TXT "first record" "another records" "a third"',
			'RP'		=> 'example.com. 300 IN RP louie.trantor.umd.edu. lam1.people.test.com.',
			'AFSDB'		=> 'example.com. 300 IN AFSDB 3 afsdb.example.com.',
			'X25'		=> 'example.com. 300 IN X25 "311 06 17 0 09 56"',
			'ISDN'		=> 'example.com. 300 IN ISDN "150 862 028 003 217" 42',
			'RT'		=> 'example.com. 300 IN RT 2 relay.prime.com.',
			'KEY'		=> 'example.com. 300 IN KEY 256 3 7 AwEAAYCXh/ZABi8kiJIDXYmyUlHzC0CHeBzqcpyZAIjC7dK1wkRYVcUvIlpTOpnOVVfcC3Py9Ui/x45qKb0LytvK7WYAe3WyOOwk5klwIqRC/0p4luafbd2yhRMF7quOBVqYrLoHwv8i9LrV+r8dhB7rXv/lkTSI6mEZsg5rDfee8Yy1',
			'PX'		=> 'example.com. 300 IN PX 10 ab.net2.it. o-ab.prmd-net2.admdb.c-it.',
			'SRV'		=> 'example.com. 300 IN SRV 20 0 5269 xmpp-server2.l.google.com.',
			'NAPTR'		=> 'example.com. 300 IN NAPTR 100 10 S SIP+D2U !^.*$!sip:customer-service@example.com! _sip._udp.example.com.',
// BROKEN			'DS'		=> 'example.com. 300 IN DS 21366 7 2 96EEB2FFD9B00CD4694E78278B5EFDAB0A80446567B69F634DA078F0 D90F01BA',
// BROKEN			'RRSIG'		=> 'example.com. 300 IN RRSIG DNSKEY 7 1 86400 20100827211706 20100822211706 57970 gov. KoWPhMtLHp8sWYZSgsMiYJKB9P71CQmh9CnxJCs5GutKfo7Jpw+nNnDL iNnsd6U1JSkf99rYRWCyOTAPC47xkHr+2Uh7n6HDJznfdCzRa/v9uwEc bXIxCZ7KfzNJewW3EvYAxDIrW6sY/4MAsjS5XM/O9LaWzw6pf7TX5obB bLI+zRECbPNTdY+RF6Fl9K0GVaEZJNYi2PRXnATwvwca2CNRWxeMT/dF5STUram3cWjH0Pkm19Gc1jbdzlZVDbUudDauWoHcc0mfH7PV1sMpe80N qK7yQ24AzAkXSiknO13itHsCe4LECUu0/OtnhHg2swwXaVTf5hqHYpzi 3bQenw==',
			'DNSKEY'	=> 'example.com. 300 IN DNSKEY 256 3 7 AwEAAYCXh/ZABi8kiJIDXYmyUlHzC0CHeBzqcpyZAIjC7dK1wkRYVcUvIlpTOpnOVVfcC3Py9Ui/x45qKb0LytvK7WYAe3WyOOwk5klwIqRC/0p4luafbd2yhRMF7quOBVqYrLoHwv8i9LrV+r8dhB7rXv/lkTSI6mEZsg5rDfee8Yy1',
			'SPF'		=> 'example.com. 300 IN SPF "v=spf1 ip4:192.168.0.1/24 mx ?all"',
// BROKEN			'DLV'		=> 'example.com. 300 IN DS 21366 7 2 96EEB2FFD9B00CD4694E78278B5EFDAB0A80446567B69F634DA078F0 D90F01BA',
		);

		foreach($rrs as $rr => $line) {

			$class_name = 'Net_DNS2_RR_' . $rr;

			//
			// create a new packet
			//
			$request = new Net_DNS2_Packet_Request('example.com', $rr, 'IN');

			//
			// parse the line
			//
			$a = Net_DNS2_RR::fromString($line);

			//
			// check that the object is right 
			//
			$this->assertTrue($a instanceof $class_name);
			
			//
			// set it on the packet
			//
			$request->answer[] = $a;
			$request->header->ancount = 1;

			//
			// get the binary packet data
			//
			$data = $request->get();
			
			//
			// parse the binary
			//
			$response = new Net_DNS2_Packet_Response($data, strlen($data));

			//
			// the answer data in the response, should match our initial line exactly
			//
			$this->assertSame($line, $response->answer[0]->toString());
		}

	}
}


?>
