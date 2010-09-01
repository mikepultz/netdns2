<?php

require_once 'Net/DNS2.php';

class Net_DNS2_ParserTest extends PHPUnit_Framework_TestCase
{
    public function testTSIG()
    {
        //
        // create a new packet
        //
        $request = new Net_DNS2_Packet_Request('example.com', 'SOA', 'IN');

        //
        // add a A record to the authority section, like an update request
        //
        $request->authority[] = Net_DNS2_RR::fromString('test.example.com A 10.10.10.10');
        $request->header->nscount = 1;

        //
        // add the TSIG as additional
        //
        $request->additional[] = Net_DNS2_RR::fromString('mykey TSIG Zm9vYmFy');
        $request->header->arcount = 1;

        $line = $request->additional[0]->name . '. ' . $request->additional[0]->ttl . ' ' . 
            $request->additional[0]->class . ' ' . $request->additional[0]->type . ' ' . 
            $request->additional[0]->algorithm . '. ' . $request->additional[0]->time_signed  . ' '.
            $request->additional[0]->fudge;

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
		$this->assertSame($line, substr($response->additional[0]->__toString(), 0, 58));
    }
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
			'NSAP'		=> 'example.com. 300 IN NSAP 0x47.0005.80.005a00.0000.0001.e133.aaaaaa000151.00',
			'KEY'		=> 'example.com. 300 IN KEY 256 3 7 AwEAAYCXh/ZABi8kiJIDXYmyUlHzC0CHeBzqcpyZAIjC7dK1wkRYVcUvIlpTOpnOVVfcC3Py9Ui/x45qKb0LytvK7WYAe3WyOOwk5klwIqRC/0p4luafbd2yhRMF7quOBVqYrLoHwv8i9LrV+r8dhB7rXv/lkTSI6mEZsg5rDfee8Yy1',
			'PX'		=> 'example.com. 300 IN PX 10 ab.net2.it. o-ab.prmd-net2.admdb.c-it.',
			'AAAA'		=> 'example.com. 300 IN AAAA 1080:0:0:0:8:800:200c:417a',
            'LOC'       => 'example.com. 300 IN LOC 42 21 54.675 N 71 06 18.343 W 24.12m 30.00m 40.00m 5.00m',
			'SRV'		=> 'example.com. 300 IN SRV 20 0 5269 xmpp-server2.l.google.com.',
			'NAPTR'		=> 'example.com. 300 IN NAPTR 100 10 S SIP+D2U !^.*$!sip:customer-service@example.com! _sip._udp.example.com.',
			'KX'		=> 'example.com. 300 IN KX 10 mx1.mrhost.ca.',
			'CERT'		=> 'example.com. 300 IN CERT 3 0 0 TUlJQ1hnSUJBQUtCZ1FDcXlqbzNFMTU0dFU1Um43ajlKTFZsOGIwcUlCSVpGWENFelZvanVJT1BsMTM0by9zcHkxSE1hQytiUGh3Wk1UYVd4QlJpZHBFbUprNlEwNFJNTXdqdkFyLzFKWjhnWThtTzdCdTh1RUROVkNWeG5rQkUzMHhDSjhHRTNzL3EyN2VWSXBCUGFtU1lkNDVKZjNIeVBRRE4yaU45RjVHdGlIa2E2OXNhcmtKUnJ3SURBUUFCQW9HQkFJaUtDQ1NEM2FFUEFjQUx1MjdWN0JmR1BYN3lDTVg0OSsyVDVwNXNJdkduQjcrQ0NZZ09QaVQybmlpMGJPNVBBOTlnZnhPQXl1WCs5Z3llclVQbUFSc1ViUzcvUndkNGorRUlOVW1DanJSK2R6dGVXT0syeGxHamFOdGNPZU5jMkVtelQyMFRsekxVeUxTWGpzMzVlU2NQK0loeVptM2xJd21vbWtNb2d1QkFrRUE0a1FsOVBxaTJ2MVBDeGJCelU4Nnphblo2b0hsV0IzMUh4MllCNmFLYXhjNkVOZHhVejFzNjU2VncrRDhSVGpoSllyeDdMVkxzZDBRaVZJM0liSjVvUUpCQU1FN3k0aHg0SCtnQU40MEdrYjNjTFZGNHNpSEZrNnA2QVZRdlpzREwvVnh3bVlOdE4rM0txT3NVcG11WXZ3a3h0ajhIQnZtckxUYStXb3NmRDQwS1U4Q1FRQ1dvNmhob1R3cmI5bmdHQmFQQ2VDc2JCaVkrRUlvbUVsSm5mcEpuYWNxQlJ5emVid0pIeXdVOGsvalNUYXJIMk5HQzJ0bG5JMzRyS1VGeDZiTTJIWUJBa0VBbXBYSWZPNkZKL1NMM1RlWGNnQ1A5U1RraVlHd2NkdnhGeGVCcDlvRDZ2cElCN2FkWlgrMko5dzY5R0VUSlI0U3loSGVOdC95ZUhqWm9YdlhKVGc3ZHdKQVpEamxwL25wNEFZV3JYaGFrMVAvNGZlaDVNSU5WVHNXQkhTNlRZNW0xRmZMUEpybklHNW1FSHNidWkvdnhuQ1JmRUR4ZlU1V1E0cS9HUkZuaVl3SHB3PT0=',
			'DNAME'		=> 'example.com. 300 IN DNAME frobozz-division.acme.example.',
// BROKEN			'DS'		=> 'example.com. 300 IN DS 21366 7 2 96EEB2FFD9B00CD4694E78278B5EFDAB0A80446567B69F634DA078F0 D90F01BA',
// BROKEN			'RRSIG'		=> 'example.com. 300 IN RRSIG DNSKEY 7 1 86400 20100827211706 20100822211706 57970 gov. KoWPhMtLHp8sWYZSgsMiYJKB9P71CQmh9CnxJCs5GutKfo7Jpw+nNnDL iNnsd6U1JSkf99rYRWCyOTAPC47xkHr+2Uh7n6HDJznfdCzRa/v9uwEc bXIxCZ7KfzNJewW3EvYAxDIrW6sY/4MAsjS5XM/O9LaWzw6pf7TX5obB bLI+zRECbPNTdY+RF6Fl9K0GVaEZJNYi2PRXnATwvwca2CNRWxeMT/dF5STUram3cWjH0Pkm19Gc1jbdzlZVDbUudDauWoHcc0mfH7PV1sMpe80N qK7yQ24AzAkXSiknO13itHsCe4LECUu0/OtnhHg2swwXaVTf5hqHYpzi 3bQenw==',
			'SSHFP'		=> 'example.com. 300 IN SSHFP 2 1 123456789abcdef67890123456789abcdef67890',
			'IPSECKEY'	=> 'example.com. 300 IN IPSECKEY 10 2 2 2001:db8:0:8002:0:0:2000:1 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==',
		    'DNSKEY'	=> 'example.com. 300 IN DNSKEY 256 3 7 AwEAAYCXh/ZABi8kiJIDXYmyUlHzC0CHeBzqcpyZAIjC7dK1wkRYVcUvIlpTOpnOVVfcC3Py9Ui/x45qKb0LytvK7WYAe3WyOOwk5klwIqRC/0p4luafbd2yhRMF7quOBVqYrLoHwv8i9LrV+r8dhB7rXv/lkTSI6mEZsg5rDfee8Yy1',
			'DHCID'		=> 'example.com. 300 IN DHCID AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=',
			'SPF'		=> 'example.com. 300 IN SPF "v=spf1 ip4:192.168.0.1/24 mx ?all"',
            'TKEY'      => 'example.com. 300 IN TKEY gss.microsoft.com. 3 123456.',
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
			$this->assertSame($line, $response->answer[0]->__toString());
		}

	}
}


?>
