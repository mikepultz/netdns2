<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */

/**
 * DNS Library for handling lookups and updates. 
 *
 * PHP Version 5
 *
 * Copyright (c) 2010, Mike Pultz <mike@mikepultz.com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *   * Neither the name of Mike Pultz nor the names of his contributors 
 *     may be used to endorse or promote products derived from this 
 *     software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRIC
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * @category   Networking
 * @package    Net_DNS2
 * @author     Mike Pultz <mike@mikepultz.com>
 * @copyright  2010 Mike Pultz <mike@mikepultz.com>
 * @license    http://www.opensource.org/licenses/bsd-license.php  BSD License
 * @version    SVN: $Id: Updater.php 63 2010-08-23 05:35:49Z mike $
 * @link       http://pear.php.net/package/Net_DNS2
 * @since      File available since Release 1.0.0
 */

class Net_DNS2_Updater extends Net_DNS2
{
	private $_packet;

	public function __construct($zone, array $options = null)
	{
		parent::__construct($options);

		//
		// create the packet
		//
		$this->_packet = new Net_DNS2_Packet_Request($zone, 'SOA', 'IN');

		//
		// make sure the opcode on the packet is set to UPDATE
		//
		$this->_packet->header->opcode = Net_DNS2_Lookups::OPCODE_UPDATE;
	}

	//
	// check that the name matches the zone specified
	//
	private function _checkName($name)
	{
		if (preg_match('/' . $this->_packet->question[0]->qname . '$/', $name) == 1) {
			return true;
		}
		return false;
	}

	//
	// add a signature to the request for authentication 
	//
	public function signature()
	{
		// TODO: figure out TSIG
	}

	//
	//   2.5.1 - Add To An RRset
	//
	//   RRs are added to the Update Section whose NAME, TYPE, TTL, RDLENGTH
	//   and RDATA are those being added, and CLASS is the same as the zone
	//   class.  Any duplicate RRs will be silently ignored by the primary
	//   master.
	//
	public function add(Net_DNS2_RR $rr)
	{
		if ($this->_checkName($rr->name) == false) {

			// TODO: throw exception;
		}

		$this->_packet->authority[] = $rr;
		return true;
	}

	//
	//   2.5.4 - Delete An RR From An RRset
	//
	//   RRs to be deleted are added to the Update Section.  The NAME, TYPE,
	//   RDLENGTH and RDATA must match the RR being deleted.  TTL must be
	//   specified as zero (0) and will otherwise be ignored by the primary
	//   master.  CLASS must be specified as NONE to distinguish this from an
	//   RR addition.  If no such RRs exist, then this Update RR will be
	//   silently ignored by the primary master.
	//
	public function delete(Net_DNS2_RR $rr)
	{
		if ($this->_checkName($rr->name) == false) {

			// TODO: throw exception;
		}

		$rr->ttl 	= 0;
		$rr->class	= 'NONE';

		$this->_packet->authority[] = $rr;
		return true;
	}

	//
	//   2.5.2 - Delete An RRset
	//
	//   One RR is added to the Update Section whose NAME and TYPE are those
	//   of the RRset to be deleted.  TTL must be specified as zero (0) and is
	//   otherwise not used by the primary master.  CLASS must be specified as
	//   ANY.  RDLENGTH must be zero (0) and RDATA must therefore be empty.
	//   If no such RRset exists, then this Update RR will be silently ignored
	//   by the primary master
	//
	public function deleteAny($name, $type)
	{
		if ($this->_checkName($name) == false) {
			// TODO: throw exception;
		}

		if (!isset(Net_DNS2_Lookups::$rr_types_id_to_class[Net_DNS2_Lookups::$rr_types_by_name[$type]])) {
			// TODO: throw execption
		}
	
		$rr 			= new Net_DNS2_Lookups::$rr_types_id_to_class[Net_DNS2_Lookups::$rr_types_by_name[$type]];

		$rr->name		= $name;
		$rr->ttl 		= 0;
		$rr->class 		= 'ANY';
		$rr->rdlength	= -1;
		$rr->rdata		= '';	

		$this->_packet->authority[] = $rr;
		return true;
	}

	//
	//   2.5.3 - Delete All RRsets From A Name
	//
	//   One RR is added to the Update Section whose NAME is that of the name
	//   to be cleansed of RRsets.  TYPE must be specified as ANY.  TTL must
	//   be specified as zero (0) and is otherwise not used by the primary
	//   master.  CLASS must be specified as ANY.  RDLENGTH must be zero (0)
	//   and RDATA must therefore be empty.  If no such RRsets exist, then
	//   this Update RR will be silently ignored by the primary master.
	//
	public function deleteAll($name)
	{
		if ($this->_checkName($name) == false) {

			// TODO: throw exception;
		}

		$rr = new Net_DNS2_RR_ANY;

		$rr->name		= $name;
		$rr->ttl 		= 0;
		$rr->type		= 'ANY';
		$rr->class		= 'ANY';
		$rr->rdlength	= -1;
		$rr->rdata		= '';

		$this->_packet->authority[] = $rr;
		return true;
	}

	//
	//   2.4.1 - RRset Exists (Value Independent)
	//
	//   At least one RR with a specified NAME and TYPE (in the zone and class
	//   specified in the Zone Section) must exist.
	//
	//   For this prerequisite, a requestor adds to the section a single RR
	//   whose NAME and TYPE are equal to that of the zone RRset whose
	//   existence is required.  RDLENGTH is zero and RDATA is therefore
	//   empty.  CLASS must be specified as ANY to differentiate this
	//   condition from that of an actual RR whose RDLENGTH is naturally zero
	//   (0) (e.g., NULL).  TTL is specified as zero (0).
	//
	public function checkExists($name, $type)
	{
		if ($this->_checkName($name) == false) {
			// TODO: throw exception;
		}

		if (!isset(Net_DNS2_Lookups::$rr_types_id_to_class[Net_DNS2_Lookups::$rr_types_by_name[$type]])) {
			// TODO: throw execption
		}
	
		$rr 			= new Net_DNS2_Lookups::$rr_types_id_to_class[Net_DNS2_Lookups::$rr_types_by_name[$type]];

		$rr->name		= $name;
		$rr->ttl 		= 0;
		$rr->class 		= 'ANY';
		$rr->rdlength	= -1;
		$rr->rdata		= '';	

		$this->_packet->answer[] = $rr;
		return true;
	}

	//
	//   2.4.2 - RRset Exists (Value Dependent)
	//
	//   A set of RRs with a specified NAME and TYPE exists and has the same
	//   members with the same RDATAs as the RRset specified here in this
	//   section.  While RRset ordering is undefined and therefore not
	//   significant to this comparison, the sets be identical in their
	//   extent.
	//
	//   For this prerequisite, a requestor adds to the section an entire
	//   RRset whose preexistence is required.  NAME and TYPE are that of the
	//   RRset being denoted.  CLASS is that of the zone.  TTL must be
	//   specified as zero (0) and is ignored when comparing RRsets for
	//   identity.
	//
	public function checkValueExists(Net_DNS2_RR $rr)
	{
		if ($this->_checkName($rr->name) == false) {

			// TODO: throw exception;
		}

		$rr->ttl = 0;

		$this->_packet->answer[] = $rr;
		return true;
	}

	//
	//   2.4.3 - RRset Does Not Exist
	//
	//   No RRs with a specified NAME and TYPE (in the zone and class denoted
	//   by the Zone Section) can exist.
	//
	//   For this prerequisite, a requestor adds to the section a single RR
	//   whose NAME and TYPE are equal to that of the RRset whose nonexistence
	//   is required.  The RDLENGTH of this record is zero (0), and RDATA
	//   field is therefore empty.  CLASS must be specified as NONE in order
	//   to distinguish this condition from a valid RR whose RDLENGTH is
	//   naturally zero (0) (for example, the NULL RR).  TTL must be specified
	//   as zero (0).
	//
	public function checkNotExists($name, $type)
	{
		if ($this->_checkName($name) == false) {
			// TODO: throw exception;
		}

		if (!isset(Net_DNS2_Lookups::$rr_types_id_to_class[Net_DNS2_Lookups::$rr_types_by_name[$type]])) {
			// TODO: throw execption
		}
	
		$rr 			= new Net_DNS2_Lookups::$rr_types_id_to_class[Net_DNS2_Lookups::$rr_types_by_name[$type]];

		$rr->name		= $name;
		$rr->ttl 		= 0;
		$rr->class 		= 'NONE';
		$rr->rdlength	= -1;
		$rr->rdata		= '';	

		$this->_packet->answer[] = $rr;
		return true;
	}

	//
	//   2.4.4 - Name Is In Use
	//
	//   Name is in use.  At least one RR with a specified NAME (in the zone
	//   and class specified by the Zone Section) must exist.  Note that this
	//   prerequisite is NOT satisfied by empty nonterminals.
	//
	//   For this prerequisite, a requestor adds to the section a single RR
	//   whose NAME is equal to that of the name whose ownership of an RR is
	//   required.  RDLENGTH is zero and RDATA is therefore empty.  CLASS must
	//   be specified as ANY to differentiate this condition from that of an
	//   actual RR whose RDLENGTH is naturally zero (0) (e.g., NULL).  TYPE
	//   must be specified as ANY to differentiate this case from that of an
	//   RRset existence test.  TTL is specified as zero (0).
	//
	public function checkNameInUse($name)
	{
		if ($this->_checkName($name) == false) {
			// TODO: throw exception;
		}

		$rr = new Net_DNS2_RR_ANY;

		$rr->name		= $name;
		$rr->ttl 		= 0;
		$rr->type		= 'ANY';
		$rr->class		= 'ANY';
		$rr->rdlength	= -1;
		$rr->rdata		= '';

		$this->_packet->answer[] = $rr;
		return true;
	}

	//
	//   2.4.5 - Name Is Not In Use
	//
	//   Name is not in use.  No RR of any type is owned by a specified NAME.
	//   Note that this prerequisite IS satisfied by empty nonterminals.
	//
	//   For this prerequisite, a requestor adds to the section a single RR
	//   whose NAME is equal to that of the name whose nonownership of any RRs
	//   is required.  RDLENGTH is zero and RDATA is therefore empty.  CLASS
	//   must be specified as NONE.  TYPE must be specified as ANY.  TTL must
	//   be specified as zero (0).
	//
	public function checkNameNotInUse($name)
	{
		if ($this->_checkName($name) == false) {
			// TODO: throw exception;
		}

		$rr = new Net_DNS2_RR_ANY;

		$rr->name		= $name;
		$rr->ttl 		= 0;
		$rr->type		= 'ANY';
		$rr->class		= 'NONE';
		$rr->rdlength	= -1;
		$rr->rdata		= '';

		$this->_packet->answer[] = $rr;
		return true;
	}

	//
	// send the request as a update 
	//
	public function update()
	{
		//
		// make sure we have some name servers set
		//
		$this->_checkServers();

		//
		// update the counts
		//
		$this->_packet->header->qdcount = count($this->_packet->question);
		$this->_packet->header->ancount = count($this->_packet->answer);
		$this->_packet->header->nscount = count($this->_packet->authority);
		$this->_packet->header->arcount = count($this->_packet->additional);

		//
		// make sure we have some data to send
		//
		if ( ($this->_packet->header->qdcount == 0) || ($this->_packet->header->nscount == 0) ) {
			// TODO: throw execption
		}

		//
		// send the packet and get back the response
		//
		$r = $this->_sendPacket($this->_packet, $this->use_tcp);
print_r($r);

		//
		// for updates, we just need to know it worked- we don't actualy need to
		// return the response object
		//
		return true;
	}
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * End:
 */
?>
