/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV6 = 0x86dd;
const bit<8>  SLICE = 32;
const bit<1>  NULL = 0;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>    egressSpec_t;
typedef bit<48>   macAddr_t;
typedef bit<128>  ip6Addr_t;
typedef bit<3>    nextHopIndex_t;
typedef bit<100> bstIndex_t;
typedef bit<1>   bstHit_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payloadLength;
    bit<8>    nextHeader;
    bit<8>    hopLimit;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
}

struct metadata {
    nextHopIndex_t   next_hop_index;
    bstIndex_t       bst_index;
    bstHit_t         bst_hit;
}

struct headers {
    ethernet_t   ethernet;
    ipv6_t       ipv6;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_next_hop_index(nextHopIndex_t nhi) {
        meta.next_hop_index = nhi;
    }

    action set_bst_index(bstIndex_t bi) {
	meta.bst_index = bi;
    }

    action ipv6_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;
    }

    action node_action(bit<(64-SLICE)> prefix, nextHopIndex_t next_hop, bstIndex_t left_index, bstIndex_t right_index) {
	if (hdr.ipv6.dstAddr[(128-SLICE-1):64] == prefix) {
	    meta.next_hop_index = next_hop;
	    meta.bst_hit = 1;
	}
	if (hdr.ipv6.dstAddr[(128-SLICE-1):64] < prefix) {
	    if (left_index == (bit<100>)NULL) {
		meta.bst_hit = 1;
	    }
	    else {
		meta.bst_index = left_index;
	    }
	}
	if (hdr.ipv6.dstAddr[(128-SLICE-1):64] > prefix) {
	    meta.next_hop_index = next_hop;
	    if (right_index == (bit<100>)NULL) {
		meta.bst_hit = 1;
	    }
	    else {
		meta.bst_index = right_index;
	    }
	}
    }

    table next_hop_table {
        key = {  
            meta.next_hop_index: exact;
        }
        actions = {
            ipv6_forward;
            drop;
	    NoAction;
        }
        size = 5;
	default_action = NoAction();
    }

    table lookup_table {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
        actions = {
            set_next_hop_index;
	    set_bst_index;
        }
	size = 32539;
    }

    table bst_0_table {
	key = {
	    meta.bst_index: exact;
	}
	actions = {
	    node_action;
	}
	size = 10100;
    }

    table bst_1_table {
	key = {
	    meta.bst_index: exact;
	}
	actions = {
	    node_action;
	}
	size = 17641;
    }

    table bst_2_table {
	key = {
	    meta.bst_index: exact;
	}
	actions = {
	    node_action;
	}
	size = 16987;
    }

    table bst_3_table {
	key = {
	    meta.bst_index: exact;
	}
	actions = {
	    node_action;
	}
	size = 16750;
    }

    table bst_4_table {
	key = {
	    meta.bst_index: exact;
	}
	actions = {
	    node_action;
	}
	size = 15279;
    }

    table bst_5_table {
	key = {
	    meta.bst_index: exact;
	}
	actions = {
	    node_action;
	}
	size = 14928;
    }

    table bst_6_table {
	key = {
	    meta.bst_index: exact;
	}
	actions = {
	    node_action;
	}
	size = 15201;
    }

    table bst_7_table {
	key = {
	    meta.bst_index: exact;
	}
	actions = {
	    node_action;
	}
	size = 15642;
    }

    table bst_8_table {
	key = {
	    meta.bst_index: exact;
	}
	actions = {
	    node_action;
	}
	size = 13490;
    }

    table bst_9_table {
	key = {
	    meta.bst_index: exact;
	}
	actions = {
	    node_action;
	}
	size = 12075;
    }

    table bst_10_table {
	key = {
	    meta.bst_index: exact;
	}
	actions = {
	    node_action;
	}
	size = 9195;
    }

    table bst_11_table {
	key = {
	    meta.bst_index: exact;
	}
	actions = {
	    node_action;
	}
	size = 5689;
    }

    table bst_12_table {
	key = {
	    meta.bst_index: exact;
	}
	actions = {
	    node_action;
	}
	size = 594;
    }

    apply {
        if (!hdr.ipv6.isValid()) {
            return;
        }

        bool foundHop = false;

	switch (lookup_table.apply().action_run) {
	    set_next_hop_index: {
		foundHop = true;
	    }
	    set_bst_index: {
		;
	    }
	    default: {
		return;
	    }
	}

        if (foundHop == false) {
            if (meta.bst_hit != 1) {
		bst_0_table.apply();
	    }
	    if (meta.bst_hit != 1) {
		bst_1_table.apply();
	    }
	    if (meta.bst_hit != 1) {
		bst_2_table.apply();
	    }
	    if (meta.bst_hit != 1) {
		bst_3_table.apply();
	    }
	    if (meta.bst_hit != 1) {
		bst_4_table.apply();
	    }
	    if (meta.bst_hit != 1) {
		bst_5_table.apply();
	    }
	    if (meta.bst_hit != 1) {
		bst_6_table.apply();
	    }
	    if (meta.bst_hit != 1) {
		bst_7_table.apply();
	    }
	    if (meta.bst_hit != 1) {
		bst_8_table.apply();
	    }
	    if (meta.bst_hit != 1) {
		bst_9_table.apply();
	    }
	    if (meta.bst_hit != 1) {
		bst_10_table.apply();
	    }
	    if (meta.bst_hit != 1) {
		bst_11_table.apply();
	    }
	    if (meta.bst_hit != 1) {
		bst_12_table.apply();
	    }
        }

	if (meta.next_hop_index == (bit<3>)NULL) {
	    return;
	}
	
        next_hop_table.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
