/*
Copyright 2021 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <core.p4>
// The following line is not needed when using Intel Tofino P4
// compiler.  It is only here to be able to use open source p4test
// with tna.p4 include file in Open-Tofino repository for syntax
// checking.
//#define __TARGET_TOFINO__ 1

#ifdef TOFINO
#include <tna.p4>
#endif

#ifdef TOFINO2
#include <t2na.p4>
#endif

#include <stdheaders.p4>

const bit<8> SLICE = 24;
const bit<16> NULL = 0;

typedef bit<2> next_hop_index_t;
typedef bit<16> bst_index_t;
typedef bit<1> bst_hit_t;

header bridge_metadata_t {
    // user-defined metadata carried over from ingress to egress.
}

struct ingress_headers_t {
    bridge_metadata_t bridge_md;
    ethernet_h ethernet;
    ipv6_h ipv6;
}

struct egress_headers_t {
    bridge_metadata_t bridge_md;
}

struct ingress_metadata_t {
    // user-defined ingress metadata
    next_hop_index_t next_hop_index;
    bst_index_t bst_index;
    bst_hit_t bst_hit;
}

struct egress_metadata_t {
    // user-defined egress metadata
}

parser ingressParserImpl(
    packet_in pkt,
    out ingress_headers_t  hdr,
    out ingress_metadata_t umd,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    state start {
        pkt.extract(ig_intr_md);
        transition parse_port_metadata;
    }
    state parse_port_metadata {
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition parse_ipv6;
    }
    state parse_ipv6 {
        pkt.extract(hdr.ipv6);
        transition accept;
    }
}

control ingressImpl(
    inout ingress_headers_t  hdr,
    inout ingress_metadata_t umd,
    in    ingress_intrinsic_metadata_t              ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t  ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t       ig_tm_md)
{
    action unicast_to_port(PortId_t p) {
        ig_tm_md.ucast_egress_port = p;
    }
    action drop_packet() {
        ig_dprsr_md.drop_ctl = 1;
        return;
    }
    action set_next_hop_index(next_hop_index_t nhi) {
        umd.next_hop_index = nhi;
    }
    action set_bst_index(bst_index_t bi) {
	    umd.bst_index = bi;
    }
    action node_decision(bit<(64-SLICE)> prefix, next_hop_index_t nhi, bst_index_t left_child, bst_index_t right_child) {
        if (hdr.ipv6.dst_addr[(128-SLICE-1):64] == prefix) {
            umd.next_hop_index = nhi;
            umd.bst_hit = 1;
        }
        if (hdr.ipv6.dst_addr[(128-SLICE-1):64] < prefix) {
            if (left_child == NULL) {
                umd.bst_hit = 1;
            }
            else {
                umd.bst_index = left_child;
            }
        }
        if (hdr.ipv6.dst_addr[(128-SLICE-1):64] > prefix) {
            umd.next_hop_index = nhi;
            if (right_child == NULL) {
                umd.bst_hit = 1;
            }
            else {
                umd.bst_index = right_child;
            }
        }
    }
    table initial_lookup_table {
        key = {
            hdr.ipv6.dst_addr[127:64] : lpm;
        }
        actions = {
            set_next_hop_index;
            set_bst_index;
            drop_packet;
        }
        const default_action = drop_packet;
	    size = 6888;
    }
    table bst_0_table {
        key = {
            umd.bst_index : exact;
        }
        actions = {
            node_decision;
        }
        size = 6833;
    }
    table bst_1_table {
        key = {
            umd.bst_index : exact;
        }
        actions = {
            node_decision;
        }
        size = 13666;
    }
    table bst_2_table {
        key = {
            umd.bst_index : exact;
        }
        actions = {
            node_decision;
        }
        size = 17186;
    }
    table bst_3_table {
        key = {
            umd.bst_index : exact;
        }
        actions = {
            node_decision;
        }
        size = 17832;
    }
    table bst_4_table {
        key = {
            umd.bst_index : exact;
        }
        actions = {
            node_decision;
        }
        size = 18476;
    }
    table bst_5_table {
        key = {
            umd.bst_index : exact;
        }
        actions = {
            node_decision;
        }
        size = 21140;
    }
    table bst_6_table {
        key = {
            umd.bst_index : exact;
        }
        actions = {
            node_decision;
        }
        size = 28756;
    }
    table bst_7_table {
        key = {
            umd.bst_index : exact;
        }
        actions = {
            node_decision;
        }
        size = 35756;
    }
    table bst_8_table {
        key = {
            umd.bst_index : exact;
        }
        actions = {
            node_decision;
        }
        size = 34710;
    }
    table bst_9_table {
        key = {
            umd.bst_index : exact;
        }
        actions = {
            node_decision;
        }
        size = 32072;
    }
    table bst_10_table {
        key = {
            umd.bst_index : exact;
        }
        actions = {
            node_decision;
        }
        size = 31724;
    }
    table bst_11_table {
        key = {
            umd.bst_index : exact;
        }
        actions = {
            node_decision;
        }
        size = 29244;
    }
    table bst_12_table {
        key = {
            umd.bst_index : exact;
        }
        actions = {
            node_decision;
        }
        size = 10098;
    }
    table bst_13_table {
        key = {
            umd.bst_index : exact;
        }
        actions = {
            node_decision;
        }
        size = 2722;
    }
    table next_hop_table {
        key = {  
            umd.next_hop_index : exact;
        }
        actions = {
            unicast_to_port;
        }
        size = 4;
    }

    apply {
        umd.bst_hit = 0;
        switch (initial_lookup_table.apply().action_run) {
            set_next_hop_index: {
                umd.bst_hit = 1;
            }
	        set_bst_index: {
                bst_0_table.apply();
                if (umd.bst_hit != 1) {
                    bst_1_table.apply();
                }
                if (umd.bst_hit != 1) {
                    bst_2_table.apply();
                }
                if (umd.bst_hit != 1) {
                    bst_3_table.apply();
                }
                if (umd.bst_hit != 1) {
                    bst_4_table.apply();
                }
                if (umd.bst_hit != 1) {
                    bst_5_table.apply();
                }
                if (umd.bst_hit != 1) {
                    bst_6_table.apply();
                }
                if (umd.bst_hit != 1) {
                    bst_7_table.apply();
                }
                if (umd.bst_hit != 1) {
                    bst_8_table.apply();
                }
                if (umd.bst_hit != 1) {
                    bst_9_table.apply();
                }
                if (umd.bst_hit != 1) {
                    bst_10_table.apply();
                }
                if (umd.bst_hit != 1) {
                    bst_11_table.apply();
                }
                if (umd.bst_hit != 1) {
                    bst_12_table.apply();
                }
                if (umd.bst_hit != 1) {
                    bst_13_table.apply();
                }
	        }
            drop_packet: {
                return;
            }
	    }
        if (umd.bst_hit != 1) {
            return;
        }
        next_hop_table.apply();
    }
}

control ingressDeparserImpl(
    packet_out pkt,
    inout ingress_headers_t  hdr,
    in    ingress_metadata_t umd,
    in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    apply {
        pkt.emit(hdr.bridge_md);
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv6);
    }
}

parser egressParserImpl(
    packet_in pkt,
    out egress_headers_t  hdr,
    out egress_metadata_t umd,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        transition parse_bridge_metadata;
    }

    state parse_bridge_metadata {
        pkt.extract(hdr.bridge_md);
        transition accept;
    }
}

control egressImpl(
    inout egress_headers_t  hdr,
    inout egress_metadata_t umd,
    in    egress_intrinsic_metadata_t                 eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t     eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t    eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
    apply {
    }
}

control egressDeparserImpl(
    packet_out pkt,
    inout egress_headers_t  hdr,
    in    egress_metadata_t umd,
    in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    apply {
    }
}

Pipeline(ingressParserImpl(),
         ingressImpl(),
         ingressDeparserImpl(),
         egressParserImpl(),
         egressImpl(),
         egressDeparserImpl()) pipe;

// In a multi-pipe Tofino device, the TNA package instantiation below
// implies that the same P4 code behavior is loaded into all of the
// pipes.

Switch(pipe) main;
