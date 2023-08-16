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
#define __TARGET_TOFINO__ 1
#include <tna.p4>

#include <stdheaders.p4>

typedef bit<2> next_hop_index_t;
typedef bit<32> bitmask_t;
typedef bit<5> bitmask_index_t;
typedef bit<32> bitstring_t;
typedef bit<19> bitstring_index_t;
typedef bit<12> hit_bitmap_t;
typedef bit<25> hash_key_t;

header bridge_metadata_t {
    // user-defined metadata carried over from ingress to egress.
}

struct ingress_headers_t {
    bridge_metadata_t bridge_md;
    ethernet_h ethernet;
    ipv4_h ipv4;
}

struct egress_headers_t {
    bridge_metadata_t bridge_md;
}

struct ingress_metadata_t {
    // user-defined ingress metadata
    next_hop_index_t next_hop_index;
    bitmask_t bitmask_24;
    bitmask_t bitmask_23;
    bitmask_t bitmask_22;
    bitmask_t bitmask_21;
    bitmask_t bitmask_20;
    bitmask_t bitmask_19;
    bitmask_t bitmask_18;
    bitmask_t bitmask_17;
    bitmask_t bitmask_16;
    bitmask_t bitmask_15;
    bitmask_t bitmask_14;
    bitmask_t bitmask_13;
    bitmask_index_t bitmask_index_24;
    bitmask_index_t bitmask_index_23;
    bitmask_index_t bitmask_index_22;
    bitmask_index_t bitmask_index_21;
    bitmask_index_t bitmask_index_20;
    bitmask_index_t bitmask_index_19;
    bitmask_index_t bitmask_index_18;
    bitmask_index_t bitmask_index_17;
    bitmask_index_t bitmask_index_16;
    bitmask_index_t bitmask_index_15;
    bitmask_index_t bitmask_index_14;
    bitmask_index_t bitmask_index_13;
    bitstring_t bitstring_24;
    bitstring_t bitstring_23;
    bitstring_t bitstring_22;
    bitstring_t bitstring_21;
    bitstring_t bitstring_20;
    bitstring_t bitstring_19;
    bitstring_t bitstring_18;
    bitstring_t bitstring_17;
    bitstring_t bitstring_16;
    bitstring_t bitstring_15;
    bitstring_t bitstring_14;
    bitstring_t bitstring_13;
    bitstring_index_t bitstring_index_24;
    bitstring_index_t bitstring_index_23;
    bitstring_index_t bitstring_index_22;
    bitstring_index_t bitstring_index_21;
    bitstring_index_t bitstring_index_20;
    bitstring_index_t bitstring_index_19;
    bitstring_index_t bitstring_index_18;
    bitstring_index_t bitstring_index_17;
    bitstring_index_t bitstring_index_16;
    bitstring_index_t bitstring_index_15;
    bitstring_index_t bitstring_index_14;
    bitstring_index_t bitstring_index_13;
    hit_bitmap_t hit_bitmap;
    hash_key_t hash_key;
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
        transition parse_ipv4;
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
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
    }
    action set_next_hop_index(next_hop_index_t nhi) {
        umd.next_hop_index = nhi;
    }
    action get_bitmask_24(bitmask_t mask) {
        umd.bitmask_24 = mask;
    }
    action get_bitmask_23(bitmask_t mask) {
        umd.bitmask_23 = mask;
    }
    action get_bitmask_22(bitmask_t mask) {
        umd.bitmask_22 = mask;
    }
    action get_bitmask_21(bitmask_t mask) {
        umd.bitmask_21 = mask;
    }
    action get_bitmask_20(bitmask_t mask) {
        umd.bitmask_20 = mask;
    }
    action get_bitmask_19(bitmask_t mask) {
        umd.bitmask_19 = mask;
    }
    action get_bitmask_18(bitmask_t mask) {
        umd.bitmask_18 = mask;
    }
    action get_bitmask_17(bitmask_t mask) {
        umd.bitmask_17 = mask;
    }
    action get_bitmask_16(bitmask_t mask) {
        umd.bitmask_16 = mask;
    }
    action get_bitmask_15(bitmask_t mask) {
        umd.bitmask_15 = mask;
    }
    action get_bitmask_14(bitmask_t mask) {
        umd.bitmask_14 = mask;
    }
    action get_bitmask_13(bitmask_t mask) {
        umd.bitmask_13 = mask;
    }
    action get_bitstring_24(bitstring_t string) {
        umd.bitstring_24 = string;
    }
    action get_bitstring_23(bitstring_t string) {
        umd.bitstring_23 = string;
    }
    action get_bitstring_22(bitstring_t string) {
        umd.bitstring_22 = string;
    }
    action get_bitstring_21(bitstring_t string) {
        umd.bitstring_21 = string;
    }
    action get_bitstring_20(bitstring_t string) {
        umd.bitstring_20 = string;
    }
    action get_bitstring_19(bitstring_t string) {
        umd.bitstring_19 = string;
    }
    action get_bitstring_18(bitstring_t string) {
        umd.bitstring_18 = string;
    }
    action get_bitstring_17(bitstring_t string) {
        umd.bitstring_17 = string;
    }
    action get_bitstring_16(bitstring_t string) {
        umd.bitstring_16 = string;
    }
    action get_bitstring_15(bitstring_t string) {
        umd.bitstring_15 = string;
    }
    action get_bitstring_14(bitstring_t string) {
        umd.bitstring_14 = string;
    }
    action get_bitstring_13(bitstring_t string) {
        umd.bitstring_13 = string;
    }
    table initial_lookup_table {
        key = {
            hdr.ipv4.dst_addr : lpm;
        }
        actions = {
            set_next_hop_index;
        }
	    size = 1465;
    }
    table bitmask_table_24 {
        key = {
            umd.bitmask_index_24 : ternary;
        }
        actions = {
            get_bitmask_24;
        }
        const entries = {
            0  &&& 0x1f : get_bitmask_24(1 << 0);
            1  &&& 0x1f : get_bitmask_24(1 << 1);
            2  &&& 0x1f : get_bitmask_24(1 << 2);
            3  &&& 0x1f : get_bitmask_24(1 << 3);
            4  &&& 0x1f : get_bitmask_24(1 << 4);
            5  &&& 0x1f : get_bitmask_24(1 << 5);
            6  &&& 0x1f : get_bitmask_24(1 << 6);
            7  &&& 0x1f : get_bitmask_24(1 << 7);
            8  &&& 0x1f : get_bitmask_24(1 << 8);
            9  &&& 0x1f : get_bitmask_24(1 << 9);
            10 &&& 0x1f : get_bitmask_24(1 << 10);
            11 &&& 0x1f : get_bitmask_24(1 << 11);
            12 &&& 0x1f : get_bitmask_24(1 << 12);
            13 &&& 0x1f : get_bitmask_24(1 << 13);
            14 &&& 0x1f : get_bitmask_24(1 << 14);
            15 &&& 0x1f : get_bitmask_24(1 << 15);
            16 &&& 0x1f : get_bitmask_24(1 << 16);
            17 &&& 0x1f : get_bitmask_24(1 << 17);
            18 &&& 0x1f : get_bitmask_24(1 << 18);
            19 &&& 0x1f : get_bitmask_24(1 << 19);
            20 &&& 0x1f : get_bitmask_24(1 << 20);
            21 &&& 0x1f : get_bitmask_24(1 << 21);
            22 &&& 0x1f : get_bitmask_24(1 << 22);
            23 &&& 0x1f : get_bitmask_24(1 << 23);
            24 &&& 0x1f : get_bitmask_24(1 << 24);
            25 &&& 0x1f : get_bitmask_24(1 << 25);
            26 &&& 0x1f : get_bitmask_24(1 << 26);
            27 &&& 0x1f : get_bitmask_24(1 << 27);
            28 &&& 0x1f : get_bitmask_24(1 << 28);
            29 &&& 0x1f : get_bitmask_24(1 << 29);
            30 &&& 0x1f : get_bitmask_24(1 << 30);
            31 &&& 0x1f : get_bitmask_24(1 << 31);
        }
    }
    table bitmask_table_23 {
        key = {
            umd.bitmask_index_23 : ternary;
        }
        actions = {
            get_bitmask_23;
        }
        const entries = {
            0  &&& 0x1f : get_bitmask_23(1 << 0);
            1  &&& 0x1f : get_bitmask_23(1 << 1);
            2  &&& 0x1f : get_bitmask_23(1 << 2);
            3  &&& 0x1f : get_bitmask_23(1 << 3);
            4  &&& 0x1f : get_bitmask_23(1 << 4);
            5  &&& 0x1f : get_bitmask_23(1 << 5);
            6  &&& 0x1f : get_bitmask_23(1 << 6);
            7  &&& 0x1f : get_bitmask_23(1 << 7);
            8  &&& 0x1f : get_bitmask_23(1 << 8);
            9  &&& 0x1f : get_bitmask_23(1 << 9);
            10 &&& 0x1f : get_bitmask_23(1 << 10);
            11 &&& 0x1f : get_bitmask_23(1 << 11);
            12 &&& 0x1f : get_bitmask_23(1 << 12);
            13 &&& 0x1f : get_bitmask_23(1 << 13);
            14 &&& 0x1f : get_bitmask_23(1 << 14);
            15 &&& 0x1f : get_bitmask_23(1 << 15);
            16 &&& 0x1f : get_bitmask_23(1 << 16);
            17 &&& 0x1f : get_bitmask_23(1 << 17);
            18 &&& 0x1f : get_bitmask_23(1 << 18);
            19 &&& 0x1f : get_bitmask_23(1 << 19);
            20 &&& 0x1f : get_bitmask_23(1 << 20);
            21 &&& 0x1f : get_bitmask_23(1 << 21);
            22 &&& 0x1f : get_bitmask_23(1 << 22);
            23 &&& 0x1f : get_bitmask_23(1 << 23);
            24 &&& 0x1f : get_bitmask_23(1 << 24);
            25 &&& 0x1f : get_bitmask_23(1 << 25);
            26 &&& 0x1f : get_bitmask_23(1 << 26);
            27 &&& 0x1f : get_bitmask_23(1 << 27);
            28 &&& 0x1f : get_bitmask_23(1 << 28);
            29 &&& 0x1f : get_bitmask_23(1 << 29);
            30 &&& 0x1f : get_bitmask_23(1 << 30);
            31 &&& 0x1f : get_bitmask_23(1 << 31);
        }
    }
    table bitmask_table_22 {
        key = {
            umd.bitmask_index_22 : ternary;
        }
        actions = {
            get_bitmask_22;
        }
        const entries = {
            0  &&& 0x1f : get_bitmask_22(1 << 0);
            1  &&& 0x1f : get_bitmask_22(1 << 1);
            2  &&& 0x1f : get_bitmask_22(1 << 2);
            3  &&& 0x1f : get_bitmask_22(1 << 3);
            4  &&& 0x1f : get_bitmask_22(1 << 4);
            5  &&& 0x1f : get_bitmask_22(1 << 5);
            6  &&& 0x1f : get_bitmask_22(1 << 6);
            7  &&& 0x1f : get_bitmask_22(1 << 7);
            8  &&& 0x1f : get_bitmask_22(1 << 8);
            9  &&& 0x1f : get_bitmask_22(1 << 9);
            10 &&& 0x1f : get_bitmask_22(1 << 10);
            11 &&& 0x1f : get_bitmask_22(1 << 11);
            12 &&& 0x1f : get_bitmask_22(1 << 12);
            13 &&& 0x1f : get_bitmask_22(1 << 13);
            14 &&& 0x1f : get_bitmask_22(1 << 14);
            15 &&& 0x1f : get_bitmask_22(1 << 15);
            16 &&& 0x1f : get_bitmask_22(1 << 16);
            17 &&& 0x1f : get_bitmask_22(1 << 17);
            18 &&& 0x1f : get_bitmask_22(1 << 18);
            19 &&& 0x1f : get_bitmask_22(1 << 19);
            20 &&& 0x1f : get_bitmask_22(1 << 20);
            21 &&& 0x1f : get_bitmask_22(1 << 21);
            22 &&& 0x1f : get_bitmask_22(1 << 22);
            23 &&& 0x1f : get_bitmask_22(1 << 23);
            24 &&& 0x1f : get_bitmask_22(1 << 24);
            25 &&& 0x1f : get_bitmask_22(1 << 25);
            26 &&& 0x1f : get_bitmask_22(1 << 26);
            27 &&& 0x1f : get_bitmask_22(1 << 27);
            28 &&& 0x1f : get_bitmask_22(1 << 28);
            29 &&& 0x1f : get_bitmask_22(1 << 29);
            30 &&& 0x1f : get_bitmask_22(1 << 30);
            31 &&& 0x1f : get_bitmask_22(1 << 31);
        }
    }
    table bitmask_table_21 {
        key = {
            umd.bitmask_index_21 : ternary;
        }
        actions = {
            get_bitmask_21;
        }
        const entries = {
            0  &&& 0x1f : get_bitmask_21(1 << 0);
            1  &&& 0x1f : get_bitmask_21(1 << 1);
            2  &&& 0x1f : get_bitmask_21(1 << 2);
            3  &&& 0x1f : get_bitmask_21(1 << 3);
            4  &&& 0x1f : get_bitmask_21(1 << 4);
            5  &&& 0x1f : get_bitmask_21(1 << 5);
            6  &&& 0x1f : get_bitmask_21(1 << 6);
            7  &&& 0x1f : get_bitmask_21(1 << 7);
            8  &&& 0x1f : get_bitmask_21(1 << 8);
            9  &&& 0x1f : get_bitmask_21(1 << 9);
            10 &&& 0x1f : get_bitmask_21(1 << 10);
            11 &&& 0x1f : get_bitmask_21(1 << 11);
            12 &&& 0x1f : get_bitmask_21(1 << 12);
            13 &&& 0x1f : get_bitmask_21(1 << 13);
            14 &&& 0x1f : get_bitmask_21(1 << 14);
            15 &&& 0x1f : get_bitmask_21(1 << 15);
            16 &&& 0x1f : get_bitmask_21(1 << 16);
            17 &&& 0x1f : get_bitmask_21(1 << 17);
            18 &&& 0x1f : get_bitmask_21(1 << 18);
            19 &&& 0x1f : get_bitmask_21(1 << 19);
            20 &&& 0x1f : get_bitmask_21(1 << 20);
            21 &&& 0x1f : get_bitmask_21(1 << 21);
            22 &&& 0x1f : get_bitmask_21(1 << 22);
            23 &&& 0x1f : get_bitmask_21(1 << 23);
            24 &&& 0x1f : get_bitmask_21(1 << 24);
            25 &&& 0x1f : get_bitmask_21(1 << 25);
            26 &&& 0x1f : get_bitmask_21(1 << 26);
            27 &&& 0x1f : get_bitmask_21(1 << 27);
            28 &&& 0x1f : get_bitmask_21(1 << 28);
            29 &&& 0x1f : get_bitmask_21(1 << 29);
            30 &&& 0x1f : get_bitmask_21(1 << 30);
            31 &&& 0x1f : get_bitmask_21(1 << 31);
        }
    }
    table bitmask_table_20 {
        key = {
            umd.bitmask_index_20 : ternary;
        }
        actions = {
            get_bitmask_20;
        }
        const entries = {
            0  &&& 0x1f : get_bitmask_20(1 << 0);
            1  &&& 0x1f : get_bitmask_20(1 << 1);
            2  &&& 0x1f : get_bitmask_20(1 << 2);
            3  &&& 0x1f : get_bitmask_20(1 << 3);
            4  &&& 0x1f : get_bitmask_20(1 << 4);
            5  &&& 0x1f : get_bitmask_20(1 << 5);
            6  &&& 0x1f : get_bitmask_20(1 << 6);
            7  &&& 0x1f : get_bitmask_20(1 << 7);
            8  &&& 0x1f : get_bitmask_20(1 << 8);
            9  &&& 0x1f : get_bitmask_20(1 << 9);
            10 &&& 0x1f : get_bitmask_20(1 << 10);
            11 &&& 0x1f : get_bitmask_20(1 << 11);
            12 &&& 0x1f : get_bitmask_20(1 << 12);
            13 &&& 0x1f : get_bitmask_20(1 << 13);
            14 &&& 0x1f : get_bitmask_20(1 << 14);
            15 &&& 0x1f : get_bitmask_20(1 << 15);
            16 &&& 0x1f : get_bitmask_20(1 << 16);
            17 &&& 0x1f : get_bitmask_20(1 << 17);
            18 &&& 0x1f : get_bitmask_20(1 << 18);
            19 &&& 0x1f : get_bitmask_20(1 << 19);
            20 &&& 0x1f : get_bitmask_20(1 << 20);
            21 &&& 0x1f : get_bitmask_20(1 << 21);
            22 &&& 0x1f : get_bitmask_20(1 << 22);
            23 &&& 0x1f : get_bitmask_20(1 << 23);
            24 &&& 0x1f : get_bitmask_20(1 << 24);
            25 &&& 0x1f : get_bitmask_20(1 << 25);
            26 &&& 0x1f : get_bitmask_20(1 << 26);
            27 &&& 0x1f : get_bitmask_20(1 << 27);
            28 &&& 0x1f : get_bitmask_20(1 << 28);
            29 &&& 0x1f : get_bitmask_20(1 << 29);
            30 &&& 0x1f : get_bitmask_20(1 << 30);
            31 &&& 0x1f : get_bitmask_20(1 << 31);
        }
    }
    table bitmask_table_19 {
        key = {
            umd.bitmask_index_19 : ternary;
        }
        actions = {
            get_bitmask_19;
        }
        const entries = {
            0  &&& 0x1f : get_bitmask_19(1 << 0);
            1  &&& 0x1f : get_bitmask_19(1 << 1);
            2  &&& 0x1f : get_bitmask_19(1 << 2);
            3  &&& 0x1f : get_bitmask_19(1 << 3);
            4  &&& 0x1f : get_bitmask_19(1 << 4);
            5  &&& 0x1f : get_bitmask_19(1 << 5);
            6  &&& 0x1f : get_bitmask_19(1 << 6);
            7  &&& 0x1f : get_bitmask_19(1 << 7);
            8  &&& 0x1f : get_bitmask_19(1 << 8);
            9  &&& 0x1f : get_bitmask_19(1 << 9);
            10 &&& 0x1f : get_bitmask_19(1 << 10);
            11 &&& 0x1f : get_bitmask_19(1 << 11);
            12 &&& 0x1f : get_bitmask_19(1 << 12);
            13 &&& 0x1f : get_bitmask_19(1 << 13);
            14 &&& 0x1f : get_bitmask_19(1 << 14);
            15 &&& 0x1f : get_bitmask_19(1 << 15);
            16 &&& 0x1f : get_bitmask_19(1 << 16);
            17 &&& 0x1f : get_bitmask_19(1 << 17);
            18 &&& 0x1f : get_bitmask_19(1 << 18);
            19 &&& 0x1f : get_bitmask_19(1 << 19);
            20 &&& 0x1f : get_bitmask_19(1 << 20);
            21 &&& 0x1f : get_bitmask_19(1 << 21);
            22 &&& 0x1f : get_bitmask_19(1 << 22);
            23 &&& 0x1f : get_bitmask_19(1 << 23);
            24 &&& 0x1f : get_bitmask_19(1 << 24);
            25 &&& 0x1f : get_bitmask_19(1 << 25);
            26 &&& 0x1f : get_bitmask_19(1 << 26);
            27 &&& 0x1f : get_bitmask_19(1 << 27);
            28 &&& 0x1f : get_bitmask_19(1 << 28);
            29 &&& 0x1f : get_bitmask_19(1 << 29);
            30 &&& 0x1f : get_bitmask_19(1 << 30);
            31 &&& 0x1f : get_bitmask_19(1 << 31);
        }
    }
    table bitmask_table_18 {
        key = {
            umd.bitmask_index_18 : ternary;
        }
        actions = {
            get_bitmask_18;
        }
        const entries = {
            0  &&& 0x1f : get_bitmask_18(1 << 0);
            1  &&& 0x1f : get_bitmask_18(1 << 1);
            2  &&& 0x1f : get_bitmask_18(1 << 2);
            3  &&& 0x1f : get_bitmask_18(1 << 3);
            4  &&& 0x1f : get_bitmask_18(1 << 4);
            5  &&& 0x1f : get_bitmask_18(1 << 5);
            6  &&& 0x1f : get_bitmask_18(1 << 6);
            7  &&& 0x1f : get_bitmask_18(1 << 7);
            8  &&& 0x1f : get_bitmask_18(1 << 8);
            9  &&& 0x1f : get_bitmask_18(1 << 9);
            10 &&& 0x1f : get_bitmask_18(1 << 10);
            11 &&& 0x1f : get_bitmask_18(1 << 11);
            12 &&& 0x1f : get_bitmask_18(1 << 12);
            13 &&& 0x1f : get_bitmask_18(1 << 13);
            14 &&& 0x1f : get_bitmask_18(1 << 14);
            15 &&& 0x1f : get_bitmask_18(1 << 15);
            16 &&& 0x1f : get_bitmask_18(1 << 16);
            17 &&& 0x1f : get_bitmask_18(1 << 17);
            18 &&& 0x1f : get_bitmask_18(1 << 18);
            19 &&& 0x1f : get_bitmask_18(1 << 19);
            20 &&& 0x1f : get_bitmask_18(1 << 20);
            21 &&& 0x1f : get_bitmask_18(1 << 21);
            22 &&& 0x1f : get_bitmask_18(1 << 22);
            23 &&& 0x1f : get_bitmask_18(1 << 23);
            24 &&& 0x1f : get_bitmask_18(1 << 24);
            25 &&& 0x1f : get_bitmask_18(1 << 25);
            26 &&& 0x1f : get_bitmask_18(1 << 26);
            27 &&& 0x1f : get_bitmask_18(1 << 27);
            28 &&& 0x1f : get_bitmask_18(1 << 28);
            29 &&& 0x1f : get_bitmask_18(1 << 29);
            30 &&& 0x1f : get_bitmask_18(1 << 30);
            31 &&& 0x1f : get_bitmask_18(1 << 31);
        }
    }
    table bitmask_table_17 {
        key = {
            umd.bitmask_index_17 : ternary;
        }
        actions = {
            get_bitmask_17;
        }
        const entries = {
            0  &&& 0x1f : get_bitmask_17(1 << 0);
            1  &&& 0x1f : get_bitmask_17(1 << 1);
            2  &&& 0x1f : get_bitmask_17(1 << 2);
            3  &&& 0x1f : get_bitmask_17(1 << 3);
            4  &&& 0x1f : get_bitmask_17(1 << 4);
            5  &&& 0x1f : get_bitmask_17(1 << 5);
            6  &&& 0x1f : get_bitmask_17(1 << 6);
            7  &&& 0x1f : get_bitmask_17(1 << 7);
            8  &&& 0x1f : get_bitmask_17(1 << 8);
            9  &&& 0x1f : get_bitmask_17(1 << 9);
            10 &&& 0x1f : get_bitmask_17(1 << 10);
            11 &&& 0x1f : get_bitmask_17(1 << 11);
            12 &&& 0x1f : get_bitmask_17(1 << 12);
            13 &&& 0x1f : get_bitmask_17(1 << 13);
            14 &&& 0x1f : get_bitmask_17(1 << 14);
            15 &&& 0x1f : get_bitmask_17(1 << 15);
            16 &&& 0x1f : get_bitmask_17(1 << 16);
            17 &&& 0x1f : get_bitmask_17(1 << 17);
            18 &&& 0x1f : get_bitmask_17(1 << 18);
            19 &&& 0x1f : get_bitmask_17(1 << 19);
            20 &&& 0x1f : get_bitmask_17(1 << 20);
            21 &&& 0x1f : get_bitmask_17(1 << 21);
            22 &&& 0x1f : get_bitmask_17(1 << 22);
            23 &&& 0x1f : get_bitmask_17(1 << 23);
            24 &&& 0x1f : get_bitmask_17(1 << 24);
            25 &&& 0x1f : get_bitmask_17(1 << 25);
            26 &&& 0x1f : get_bitmask_17(1 << 26);
            27 &&& 0x1f : get_bitmask_17(1 << 27);
            28 &&& 0x1f : get_bitmask_17(1 << 28);
            29 &&& 0x1f : get_bitmask_17(1 << 29);
            30 &&& 0x1f : get_bitmask_17(1 << 30);
            31 &&& 0x1f : get_bitmask_17(1 << 31);
        }
    }
    table bitmask_table_16 {
        key = {
            umd.bitmask_index_16 : ternary;
        }
        actions = {
            get_bitmask_16;
        }
        const entries = {
            0  &&& 0x1f : get_bitmask_16(1 << 0);
            1  &&& 0x1f : get_bitmask_16(1 << 1);
            2  &&& 0x1f : get_bitmask_16(1 << 2);
            3  &&& 0x1f : get_bitmask_16(1 << 3);
            4  &&& 0x1f : get_bitmask_16(1 << 4);
            5  &&& 0x1f : get_bitmask_16(1 << 5);
            6  &&& 0x1f : get_bitmask_16(1 << 6);
            7  &&& 0x1f : get_bitmask_16(1 << 7);
            8  &&& 0x1f : get_bitmask_16(1 << 8);
            9  &&& 0x1f : get_bitmask_16(1 << 9);
            10 &&& 0x1f : get_bitmask_16(1 << 10);
            11 &&& 0x1f : get_bitmask_16(1 << 11);
            12 &&& 0x1f : get_bitmask_16(1 << 12);
            13 &&& 0x1f : get_bitmask_16(1 << 13);
            14 &&& 0x1f : get_bitmask_16(1 << 14);
            15 &&& 0x1f : get_bitmask_16(1 << 15);
            16 &&& 0x1f : get_bitmask_16(1 << 16);
            17 &&& 0x1f : get_bitmask_16(1 << 17);
            18 &&& 0x1f : get_bitmask_16(1 << 18);
            19 &&& 0x1f : get_bitmask_16(1 << 19);
            20 &&& 0x1f : get_bitmask_16(1 << 20);
            21 &&& 0x1f : get_bitmask_16(1 << 21);
            22 &&& 0x1f : get_bitmask_16(1 << 22);
            23 &&& 0x1f : get_bitmask_16(1 << 23);
            24 &&& 0x1f : get_bitmask_16(1 << 24);
            25 &&& 0x1f : get_bitmask_16(1 << 25);
            26 &&& 0x1f : get_bitmask_16(1 << 26);
            27 &&& 0x1f : get_bitmask_16(1 << 27);
            28 &&& 0x1f : get_bitmask_16(1 << 28);
            29 &&& 0x1f : get_bitmask_16(1 << 29);
            30 &&& 0x1f : get_bitmask_16(1 << 30);
            31 &&& 0x1f : get_bitmask_16(1 << 31);
        }
    }
    table bitmask_table_15 {
        key = {
            umd.bitmask_index_15 : ternary;
        }
        actions = {
            get_bitmask_15;
        }
        const entries = {
            0  &&& 0x1f : get_bitmask_15(1 << 0);
            1  &&& 0x1f : get_bitmask_15(1 << 1);
            2  &&& 0x1f : get_bitmask_15(1 << 2);
            3  &&& 0x1f : get_bitmask_15(1 << 3);
            4  &&& 0x1f : get_bitmask_15(1 << 4);
            5  &&& 0x1f : get_bitmask_15(1 << 5);
            6  &&& 0x1f : get_bitmask_15(1 << 6);
            7  &&& 0x1f : get_bitmask_15(1 << 7);
            8  &&& 0x1f : get_bitmask_15(1 << 8);
            9  &&& 0x1f : get_bitmask_15(1 << 9);
            10 &&& 0x1f : get_bitmask_15(1 << 10);
            11 &&& 0x1f : get_bitmask_15(1 << 11);
            12 &&& 0x1f : get_bitmask_15(1 << 12);
            13 &&& 0x1f : get_bitmask_15(1 << 13);
            14 &&& 0x1f : get_bitmask_15(1 << 14);
            15 &&& 0x1f : get_bitmask_15(1 << 15);
            16 &&& 0x1f : get_bitmask_15(1 << 16);
            17 &&& 0x1f : get_bitmask_15(1 << 17);
            18 &&& 0x1f : get_bitmask_15(1 << 18);
            19 &&& 0x1f : get_bitmask_15(1 << 19);
            20 &&& 0x1f : get_bitmask_15(1 << 20);
            21 &&& 0x1f : get_bitmask_15(1 << 21);
            22 &&& 0x1f : get_bitmask_15(1 << 22);
            23 &&& 0x1f : get_bitmask_15(1 << 23);
            24 &&& 0x1f : get_bitmask_15(1 << 24);
            25 &&& 0x1f : get_bitmask_15(1 << 25);
            26 &&& 0x1f : get_bitmask_15(1 << 26);
            27 &&& 0x1f : get_bitmask_15(1 << 27);
            28 &&& 0x1f : get_bitmask_15(1 << 28);
            29 &&& 0x1f : get_bitmask_15(1 << 29);
            30 &&& 0x1f : get_bitmask_15(1 << 30);
            31 &&& 0x1f : get_bitmask_15(1 << 31);
        }
    }
    table bitmask_table_14 {
        key = {
            umd.bitmask_index_14 : ternary;
        }
        actions = {
            get_bitmask_14;
        }
        const entries = {
            0  &&& 0x1f : get_bitmask_14(1 << 0);
            1  &&& 0x1f : get_bitmask_14(1 << 1);
            2  &&& 0x1f : get_bitmask_14(1 << 2);
            3  &&& 0x1f : get_bitmask_14(1 << 3);
            4  &&& 0x1f : get_bitmask_14(1 << 4);
            5  &&& 0x1f : get_bitmask_14(1 << 5);
            6  &&& 0x1f : get_bitmask_14(1 << 6);
            7  &&& 0x1f : get_bitmask_14(1 << 7);
            8  &&& 0x1f : get_bitmask_14(1 << 8);
            9  &&& 0x1f : get_bitmask_14(1 << 9);
            10 &&& 0x1f : get_bitmask_14(1 << 10);
            11 &&& 0x1f : get_bitmask_14(1 << 11);
            12 &&& 0x1f : get_bitmask_14(1 << 12);
            13 &&& 0x1f : get_bitmask_14(1 << 13);
            14 &&& 0x1f : get_bitmask_14(1 << 14);
            15 &&& 0x1f : get_bitmask_14(1 << 15);
            16 &&& 0x1f : get_bitmask_14(1 << 16);
            17 &&& 0x1f : get_bitmask_14(1 << 17);
            18 &&& 0x1f : get_bitmask_14(1 << 18);
            19 &&& 0x1f : get_bitmask_14(1 << 19);
            20 &&& 0x1f : get_bitmask_14(1 << 20);
            21 &&& 0x1f : get_bitmask_14(1 << 21);
            22 &&& 0x1f : get_bitmask_14(1 << 22);
            23 &&& 0x1f : get_bitmask_14(1 << 23);
            24 &&& 0x1f : get_bitmask_14(1 << 24);
            25 &&& 0x1f : get_bitmask_14(1 << 25);
            26 &&& 0x1f : get_bitmask_14(1 << 26);
            27 &&& 0x1f : get_bitmask_14(1 << 27);
            28 &&& 0x1f : get_bitmask_14(1 << 28);
            29 &&& 0x1f : get_bitmask_14(1 << 29);
            30 &&& 0x1f : get_bitmask_14(1 << 30);
            31 &&& 0x1f : get_bitmask_14(1 << 31);
        }
    }
    table bitmask_table_13 {
        key = {
            umd.bitmask_index_13 : ternary;
        }
        actions = {
            get_bitmask_13;
        }
        const entries = {
            0  &&& 0x1f : get_bitmask_13(1 << 0);
            1  &&& 0x1f : get_bitmask_13(1 << 1);
            2  &&& 0x1f : get_bitmask_13(1 << 2);
            3  &&& 0x1f : get_bitmask_13(1 << 3);
            4  &&& 0x1f : get_bitmask_13(1 << 4);
            5  &&& 0x1f : get_bitmask_13(1 << 5);
            6  &&& 0x1f : get_bitmask_13(1 << 6);
            7  &&& 0x1f : get_bitmask_13(1 << 7);
            8  &&& 0x1f : get_bitmask_13(1 << 8);
            9  &&& 0x1f : get_bitmask_13(1 << 9);
            10 &&& 0x1f : get_bitmask_13(1 << 10);
            11 &&& 0x1f : get_bitmask_13(1 << 11);
            12 &&& 0x1f : get_bitmask_13(1 << 12);
            13 &&& 0x1f : get_bitmask_13(1 << 13);
            14 &&& 0x1f : get_bitmask_13(1 << 14);
            15 &&& 0x1f : get_bitmask_13(1 << 15);
            16 &&& 0x1f : get_bitmask_13(1 << 16);
            17 &&& 0x1f : get_bitmask_13(1 << 17);
            18 &&& 0x1f : get_bitmask_13(1 << 18);
            19 &&& 0x1f : get_bitmask_13(1 << 19);
            20 &&& 0x1f : get_bitmask_13(1 << 20);
            21 &&& 0x1f : get_bitmask_13(1 << 21);
            22 &&& 0x1f : get_bitmask_13(1 << 22);
            23 &&& 0x1f : get_bitmask_13(1 << 23);
            24 &&& 0x1f : get_bitmask_13(1 << 24);
            25 &&& 0x1f : get_bitmask_13(1 << 25);
            26 &&& 0x1f : get_bitmask_13(1 << 26);
            27 &&& 0x1f : get_bitmask_13(1 << 27);
            28 &&& 0x1f : get_bitmask_13(1 << 28);
            29 &&& 0x1f : get_bitmask_13(1 << 29);
            30 &&& 0x1f : get_bitmask_13(1 << 30);
            31 &&& 0x1f : get_bitmask_13(1 << 31);
        }
    }
    table bitstring_table_24 {
        key = {
            umd.bitstring_index_24 : exact;
        }
        actions = {
            get_bitstring_24;
        }
        size = 524288;
    }
    table bitstring_table_23 {
        key = {
            umd.bitstring_index_23 : exact;
        }
        actions = {
            get_bitstring_23;
        }
        size = 262144;
    }
    table bitstring_table_22 {
        key = {
            umd.bitstring_index_22 : exact;
        }
        actions = {
            get_bitstring_22;
        }
        size = 131072;
    }
    table bitstring_table_21 {
        key = {
            umd.bitstring_index_21 : exact;
        }
        actions = {
            get_bitstring_21;
        }
        size = 65536;
    }
    table bitstring_table_20 {
        key = {
            umd.bitstring_index_20 : exact;
        }
        actions = {
            get_bitstring_20;
        }
        size = 32768;
    }
    table bitstring_table_19 {
        key = {
            umd.bitstring_index_19 : exact;
        }
        actions = {
            get_bitstring_19;
        }
        size = 16384;
    }
    table bitstring_table_18 {
        key = {
            umd.bitstring_index_18 : exact;
        }
        actions = {
            get_bitstring_18;
        }
        size = 8192;
    }
    table bitstring_table_17 {
        key = {
            umd.bitstring_index_17 : exact;
        }
        actions = {
            get_bitstring_17;
        }
        size = 4096;
    }
    table bitstring_table_16 {
        key = {
            umd.bitstring_index_16 : exact;
        }
        actions = {
            get_bitstring_16;
        }
        size = 2048;
    }
    table bitstring_table_15 {
        key = {
            umd.bitstring_index_15 : exact;
        }
        actions = {
            get_bitstring_15;
        }
        size = 1024;
    }
    table bitstring_table_14 {
        key = {
            umd.bitstring_index_14 : exact;
        }
        actions = {
            get_bitstring_14;
        }
        size = 512;
    }
    table bitstring_table_13 {
        key = {
            umd.bitstring_index_13 : exact;
        }
        actions = {
            get_bitstring_13;
        }
        size = 256;
    }
    table key_table {
        key = {
            umd.hit_bitmap : ternary;
        }
        actions = {
            set_hash_key;
        }
        const entries = {
            0x800 &&& 0x800 : set_hash_key(((bit<25>)(hdr.ipv4.dstAddr[31:8] ++ (bit<1>)1)) << 0);
            0x400 &&& 0xc00 : set_hash_key(((bit<25>)(hdr.ipv4.dstAddr[31:9] ++ (bit<1>)1)) << 1);
            0x200 &&& 0xe00 : set_hash_key(((bit<25>)(hdr.ipv4.dstAddr[31:10] ++ (bit<1>)1)) << 2);
            0x100 &&& 0xf00 : set_hash_key(((bit<25>)(hdr.ipv4.dstAddr[31:11] ++ (bit<1>)1)) << 3);
            0x080 &&& 0xf80 : set_hash_key(((bit<25>)(hdr.ipv4.dstAddr[31:12] ++ (bit<1>)1)) << 4);
            0x040 &&& 0xfc0 : set_hash_key(((bit<25>)(hdr.ipv4.dstAddr[31:13] ++ (bit<1>)1)) << 5);
            0x020 &&& 0xfe0 : set_hash_key(((bit<25>)(hdr.ipv4.dstAddr[31:14] ++ (bit<1>)1)) << 6);
            0x010 &&& 0xff0 : set_hash_key(((bit<25>)(hdr.ipv4.dstAddr[31:15] ++ (bit<1>)1)) << 7);
            0x008 &&& 0xff8 : set_hash_key(((bit<25>)(hdr.ipv4.dstAddr[31:16] ++ (bit<1>)1)) << 8);
            0x004 &&& 0xffc : set_hash_key(((bit<25>)(hdr.ipv4.dstAddr[31:17] ++ (bit<1>)1)) << 9);
            0x002 &&& 0xffe : set_hash_key(((bit<25>)(hdr.ipv4.dstAddr[31:18] ++ (bit<1>)1)) << 10);
            0x001 &&& 0xfff : set_hash_key(((bit<25>)(hdr.ipv4.dstAddr[31:19] ++ (bit<1>)1)) << 11);
        }
    }
    table hash_table {
        key = {
            umd.hash_key : exact;
        }
        actions = {
            set_next_hop_index;
        }
	    size = 901619;
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
        if(initial_lookup_table.apply().miss) {
            umd.bitmask_index_24 = (bit<5>)(hdr.ipv4.dst_addr[31:8] % 32);
            umd.bitstring_index_24 = (bit<19>)(hdr.ipv4.dst_addr[31:8] / 32);
            bitmask_table_24.apply();
            bitstring_table_24.apply();
            umd.hit_bitmap[11] = !!(umd.bitmask_24 & umd.bitstring_24);

			umd.bitmask_index_23 = (bit<5>)(hdr.ipv4.dst_addr[31:9] % 32);
			umd.bitstring_index_23 = (bit<19>)(hdr.ipv4.dst_addr[31:9] / 32);
			bitmask_table_23.apply();
			bitstring_table_23.apply();
			umd.hit_bitmap[10] = !!(umd.bitmask_23 & umd.bitstring_23);

			umd.bitmask_index_22 = (bit<5>)(hdr.ipv4.dst_addr[31:10] % 32);
			umd.bitstring_index_22 = (bit<19>)(hdr.ipv4.dst_addr[31:10] / 32);
			bitmask_table_22.apply();
			bitstring_table_22.apply();
			umd.hit_bitmap[9] = !!(umd.bitmask_22 & umd.bitstring_22);

			umd.bitmask_index_21 = (bit<5>)(hdr.ipv4.dst_addr[31:11] % 32);
			umd.bitstring_index_21 = (bit<19>)(hdr.ipv4.dst_addr[31:11] / 32);
			bitmask_table_21.apply();
			bitstring_table_21.apply();
			umd.hit_bitmap[8] = !!(umd.bitmask_21 & umd.bitstring_21);

			umd.bitmask_index_20 = (bit<5>)(hdr.ipv4.dst_addr[31:12] % 32);
			umd.bitstring_index_20 = (bit<19>)(hdr.ipv4.dst_addr[31:12] / 32);
			bitmask_table_20.apply();
			bitstring_table_20.apply();
			umd.hit_bitmap[7] = !!(umd.bitmask_20 & umd.bitstring_20);

			umd.bitmask_index_19 = (bit<5>)(hdr.ipv4.dst_addr[31:13] % 32);
			umd.bitstring_index_19 = (bit<19>)(hdr.ipv4.dst_addr[31:13] / 32);
			bitmask_table_19.apply();
			bitstring_table_19.apply();
			umd.hit_bitmap[6] = !!(umd.bitmask_19 & umd.bitstring_19);

			umd.bitmask_index_18 = (bit<5>)(hdr.ipv4.dst_addr[31:14] % 32);
			umd.bitstring_index_18 = (bit<19>)(hdr.ipv4.dst_addr[31:14] / 32);
			bitmask_table_18.apply();
			bitstring_table_18.apply();
			umd.hit_bitmap[5] = !!(umd.bitmask_18 & umd.bitstring_18);

			umd.bitmask_index_17 = (bit<5>)(hdr.ipv4.dst_addr[31:15] % 32);
			umd.bitstring_index_17 = (bit<19>)(hdr.ipv4.dst_addr[31:15] / 32);
			bitmask_table_17.apply();
			bitstring_table_17.apply();
			umd.hit_bitmap[4] = !!(umd.bitmask_17 & umd.bitstring_17);

			umd.bitmask_index_16 = (bit<5>)(hdr.ipv4.dst_addr[31:16] % 32);
			umd.bitstring_index_16 = (bit<19>)(hdr.ipv4.dst_addr[31:16] / 32);
			bitmask_table_16.apply();
			bitstring_table_16.apply();
			umd.hit_bitmap[3] = !!(umd.bitmask_16 & umd.bitstring_16);

			umd.bitmask_index_15 = (bit<5>)(hdr.ipv4.dst_addr[31:17] % 32);
			umd.bitstring_index_15 = (bit<19>)(hdr.ipv4.dst_addr[31:17] / 32);
			bitmask_table_15.apply();
			bitstring_table_15.apply();
			umd.hit_bitmap[2] = !!(umd.bitmask_15 & umd.bitstring_15);

			umd.bitmask_index_14 = (bit<5>)(hdr.ipv4.dst_addr[31:18] % 32);
			umd.bitstring_index_14 = (bit<19>)(hdr.ipv4.dst_addr[31:18] / 32);
			bitmask_table_14.apply();
			bitstring_table_14.apply();
			umd.hit_bitmap[1] = !!(umd.bitmask_14 & umd.bitstring_14);

			umd.bitmask_index_13 = (bit<5>)(hdr.ipv4.dst_addr[31:19] % 32);
			umd.bitstring_index_13 = (bit<19>)(hdr.ipv4.dst_addr[31:19] / 32);
			bitmask_table_13.apply();
			bitstring_table_13.apply();
			umd.hit_bitmap[0] = !!(umd.bitmask_13 & umd.bitstring_13);

            key_table.apply();
            hash_table.apply();
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
        pkt.emit(hdr.ipv4);
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