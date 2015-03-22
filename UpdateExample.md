# Basic Update Syntax #

```

require_once("Net_DNS2/Net/DNS2.php");

//
// create a new Updater object
//
$u = new Net_DNS2_Updater('example.com', array('nameservers' => array('192.168.0.1')));

try {
	//
	// create a new MX RR object to add to the example.com zone
	//
	$mx = Net_DNS2_RR::fromString('test.example.com MX 10 mail.google.com');

	//
	// add the record
	//
	$u->add($mx);

	//
	// add a TSIG to authenticate the request
	//
	$u->signTSIG('my-key', '9dnf93asdf39fs');

	//
	// execute the request
	//
        $u->update();
        
} catch(Net_DNS2_Exception $e) {

	echo "::update() failed: ", $e->getMessage(), "\n";
}

```