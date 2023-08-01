/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>    egressSpec_t;
typedef bit<48>   macAddr_t;
typedef bit<32>   ip4Addr_t;
typedef bit<2>    nextHopIndex_t;
typedef bit<19>   bitmapIndex_t;
typedef bit<5>    bitstringIndex_t;
typedef bit<32>   bitstring_t;
typedef bit<25>   hashKey_t;
typedef bit<32>   bitmapMask_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    nextHopIndex_t   next_hop_index;
    bitmapIndex_t    bitmap_index;
    bitstringIndex_t bitstring_index;
    hashKey_t        hash_key;
    bitmapMask_t     bitmap_mask
    bitstring_t      bitstring;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
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
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
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

    action get_bitstring(bitstring_t bitstring) {
        meta.bitstring = bitstring;
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action get_bitmap_mask(bitmapMask_t mask) {
        meta.bitmap_mask = mask;
    }

    table bitmap_mask_table {
        key = {
            meta.bitstring_index : ternary;
        }
        actions = {
            get_bitmap_mask;
        }
        const entries = {
            0  &&& 0x1f : get_bitmap_mask(1 << 0);
            1  &&& 0x1f : get_bitmap_mask(1 << 1);
            2  &&& 0x1f : get_bitmap_mask(1 << 2);
            3  &&& 0x1f : get_bitmap_mask(1 << 3);
            4  &&& 0x1f : get_bitmap_mask(1 << 4);
            5  &&& 0x1f : get_bitmap_mask(1 << 5);
            6  &&& 0x1f : get_bitmap_mask(1 << 6);
            7  &&& 0x1f : get_bitmap_mask(1 << 7);
            8  &&& 0x1f : get_bitmap_mask(1 << 8);
            9  &&& 0x1f : get_bitmap_mask(1 << 9);
            10 &&& 0x1f : get_bitmap_mask(1 << 10);
            11 &&& 0x1f : get_bitmap_mask(1 << 11);
            12 &&& 0x1f : get_bitmap_mask(1 << 12);
            13 &&& 0x1f : get_bitmap_mask(1 << 13);
            14 &&& 0x1f : get_bitmap_mask(1 << 14);
            15 &&& 0x1f : get_bitmap_mask(1 << 15);
            16 &&& 0x1f : get_bitmap_mask(1 << 16);
            17 &&& 0x1f : get_bitmap_mask(1 << 17);
            18 &&& 0x1f : get_bitmap_mask(1 << 18);
            19 &&& 0x1f : get_bitmap_mask(1 << 19);
            20 &&& 0x1f : get_bitmap_mask(1 << 20);
            21 &&& 0x1f : get_bitmap_mask(1 << 21);
            22 &&& 0x1f : get_bitmap_mask(1 << 22);
            23 &&& 0x1f : get_bitmap_mask(1 << 23);
            24 &&& 0x1f : get_bitmap_mask(1 << 24);
            25 &&& 0x1f : get_bitmap_mask(1 << 25);
            26 &&& 0x1f : get_bitmap_mask(1 << 26);
            27 &&& 0x1f : get_bitmap_mask(1 << 27);
            28 &&& 0x1f : get_bitmap_mask(1 << 28);
            29 &&& 0x1f : get_bitmap_mask(1 << 29);
            30 &&& 0x1f : get_bitmap_mask(1 << 30);
            31 &&& 0x1f : get_bitmap_mask(1 << 31);
        }
    }

    table next_hop_table {
        key = {  
            meta.next_hop_index: exact;
        }
        actions = {
            ipv4_forward;
            drop;
	        NoAction;
        }
        size = 5;
	    default_action = NoAction();
    }

    table lookup_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_next_hop_index;
        }
	    size = 1465;
    }

    table hash_table {
        key = {
            meta.hash_key: exact;
        }
        actions = {
            set_next_hop_index;
        }
	    size = 901619;
    }

    table bitmap_24_table {
        key = {
            meta.bitmap_index: exact;
        }
        actions = {
            get_bitstring;
        }
	    size = 524288;
    }

    table bitmap_23_table {
        key = {
            meta.bitmap_index: exact;
        }
        actions = {
            get_bitstring;
        }
	    size = 262144;
    }

    table bitmap_22_table {
        key = {
            meta.bitmap_index: exact;
        }
        actions = {
            get_bitstring;
        }
	    size = 131072;
    }

    table bitmap_21_table {
        key = {
            meta.bitmap_index: exact;
        }
        actions = {
            get_bitstring;
        }
	    size = 65536;
    }

    table bitmap_20_table {
        key = {
            meta.bitmap_index: exact;
        }
        actions = {
            get_bitstring;
        }
	    size = 32768;
    }

    table bitmap_19_table {
        key = {
            meta.bitmap_index: exact;
        }
        actions = {
            get_bitstring;
        }
	    size = 16384;
    }

    table bitmap_18_table {
        key = {
            meta.bitmap_index: exact;
        }
        actions = {
            get_bitstring;
        }
	    size = 8192;
    }

    table bitmap_17_table {
        key = {
            meta.bitmap_index: exact;
        }
        actions = {
            get_bitstring;
        }
	    size = 4096;
    }

    table bitmap_16_table {
        key = {
            meta.bitmap_index: exact;
        }
        actions = {
            get_bitstring;
        }
	    size = 2048;
    }

    table bitmap_15_table {
        key = {
            meta.bitmap_index: exact;
        }
        actions = {
            get_bitstring;
        }
	    size = 1024;
    }

    table bitmap_14_table {
        key = {
            meta.bitmap_index: exact;
        }
        actions = {
            get_bitstring;
        }
	    size = 512;
    }

    table bitmap_13_table {
        key = {
            meta.bitmap_index: exact;
        }
        actions = {
            get_bitstring;
        }
	    size = 256;
    }

    apply {
        if (!hdr.ipv4.isValid()) {
            return;
        }

        bool foundHop = false;
        bool skipToHash = false;

        if(lookup_table.apply().hit) {
            foundHop = true;
        }

        if(foundHop == false) {
            if(skipToHash == false) {
                meta.bitmap_index = (bit<19>)(hdr.ipv4.dstAddr[31:8] / 32);
                meta.bitstring_index = (bit<5>)(hdr.ipv4.dstAddr[31:8] % 32);

                bitmap_mask_table.apply();
                bitmap_24_table.apply();
                if(meta.bitmap_mask & meta.bitstring != 0){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:8] ++ (bit<1>)1)) << 0;
                }
            }

            if(skipToHash == false) {
                meta.bitmap_index = (bit<19>)(hdr.ipv4.dstAddr[31:9] / 32);
                meta.bitstring_index = (bit<5>)(hdr.ipv4.dstAddr[31:9] % 32);

                bitmap_mask_table.apply();
                bitmap_23_table.apply();
                if(meta.bitmap_mask & meta.bitstring != 0){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:9] ++ (bit<1>)1)) << 1;
                }
            }

            if(skipToHash == false) {
                meta.bitmap_index = (bit<19>)(hdr.ipv4.dstAddr[31:10] / 32);
                meta.bitstring_index = (bit<5>)(hdr.ipv4.dstAddr[31:10] % 32);

                bitmap_mask_table.apply();
                bitmap_22_table.apply();
                if(meta.bitmap_mask & meta.bitstring != 0){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:10] ++ (bit<1>)1)) << 2;
                }
            }

            if(skipToHash == false) {
                meta.bitmap_index = (bit<19>)(hdr.ipv4.dstAddr[31:11] / 32);
                meta.bitstring_index = (bit<5>)(hdr.ipv4.dstAddr[31:11] % 32);

                bitmap_mask_table.apply();
                bitmap_21_table.apply();
                if(meta.bitmap_mask & meta.bitstring != 0){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:11] ++ (bit<1>)1)) << 3;
                }
            }

            if(skipToHash == false) {
                meta.bitmap_index = (bit<19>)(hdr.ipv4.dstAddr[31:12] / 32);
                meta.bitstring_index = (bit<5>)(hdr.ipv4.dstAddr[31:12] % 32);

                bitmap_mask_table.apply();
                bitmap_20_table.apply();
                if(meta.bitmap_mask & meta.bitstring != 0){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:12] ++ (bit<1>)1)) << 4;
                }
            }

            if(skipToHash == false) {
                meta.bitmap_index = (bit<19>)(hdr.ipv4.dstAddr[31:13] / 32);
                meta.bitstring_index = (bit<5>)(hdr.ipv4.dstAddr[31:13] % 32);

                bitmap_mask_table.apply();
                bitmap_19_table.apply();
                if(meta.bitmap_mask & meta.bitstring != 0){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:13] ++ (bit<1>)1)) << 5;
                }
            }

            if(skipToHash == false) {
                meta.bitmap_index = (bit<19>)(hdr.ipv4.dstAddr[31:14] / 32);
                meta.bitstring_index = (bit<5>)(hdr.ipv4.dstAddr[31:14] % 32);

                bitmap_mask_table.apply();
                bitmap_18_table.apply();
                if(meta.bitmap_mask & meta.bitstring != 0){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:14] ++ (bit<1>)1)) << 6;
                }
            }

            if(skipToHash == false) {
                meta.bitmap_index = (bit<19>)(hdr.ipv4.dstAddr[31:15] / 32);
                meta.bitstring_index = (bit<5>)(hdr.ipv4.dstAddr[31:15] % 32);

                bitmap_mask_table.apply();
                bitmap_17_table.apply();
                if(meta.bitmap_mask & meta.bitstring != 0){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:15] ++ (bit<1>)1)) << 7;
                }
            }

            if(skipToHash == false) {
                meta.bitmap_index = (bit<19>)(hdr.ipv4.dstAddr[31:16] / 32);
                meta.bitstring_index = (bit<5>)(hdr.ipv4.dstAddr[31:16] % 32);

                bitmap_mask_table.apply();
                bitmap_16_table.apply();
                if(meta.bitmap_mask & meta.bitstring != 0){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:16] ++ (bit<1>)1)) << 8;
                }
            }

            if(skipToHash == false) {
                meta.bitmap_index = (bit<19>)(hdr.ipv4.dstAddr[31:17] / 32);
                meta.bitstring_index = (bit<5>)(hdr.ipv4.dstAddr[31:17] % 32);

                bitmap_mask_table.apply();
                bitmap_15_table.apply();
                if(meta.bitmap_mask & meta.bitstring != 0){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:17] ++ (bit<1>)1)) << 9;
                }
            }

            if(skipToHash == false) {
                meta.bitmap_index = (bit<19>)(hdr.ipv4.dstAddr[31:18] / 32);
                meta.bitstring_index = (bit<5>)(hdr.ipv4.dstAddr[31:18] % 32);

                bitmap_mask_table.apply();
                bitmap_14_table.apply();
                if(meta.bitmap_mask & meta.bitstring != 0){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:18] ++ (bit<1>)1)) << 10;
                }
            }

            if(skipToHash == false) {
                meta.bitmap_index = (bit<19>)(hdr.ipv4.dstAddr[31:19] / 32);
                meta.bitstring_index = (bit<5>)(hdr.ipv4.dstAddr[31:19] % 32);

                bitmap_mask_table.apply();
                bitmap_13_table.apply();
                if(meta.bitmap_mask & meta.bitstring != 0){
                    skipToHash = true;
                    meta.hash_key = ((bit<25>)(hdr.ipv4.dstAddr[31:19] ++ (bit<1>)1)) << 11;
                }
            }

            if(!hash_table.apply().hit){
                return;
            }
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
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
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
