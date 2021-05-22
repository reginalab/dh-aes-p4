/*
    This implementation is derived in part from the reference
    Princeton-Cabernet AES-128 encryption in P4 implementation, which carries 
    the following notice:

    AES-128 encryption in P4

    Copyright (C) 2019 Xiaoqi Chen, Princeton University
    Copyright (C) 2021 Ramon Fontes, UFRN/Brazil
    Copyright (C) 2021 Emídio Neto, UFRN/Brazil
    Copyright (C) 2021 Fabricio Rodríguez, Unicamp/Brazil

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// Standard headers
#include <core.p4>
#include <v1model.p4>

// Max entries into the register
#define MAX_KEYS 8

// useful for DH
typedef bit<256> keys_t;
typedef bit<48> macAddr_t;
typedef bit<240> data_t;

register<keys_t>(MAX_KEYS) register_pub_keys;
register<keys_t>(MAX_KEYS) register_priv_keys;
register<keys_t>(MAX_KEYS) register_secret_keys;
register<data_t>(MAX_KEYS) register_data;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
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
    macAddr_t srcAddr;
    macAddr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

#define ETHERTYPE_AES_TOY 0x9999
#define TYPE_PROBE 0x812
#define TYPE_PROBE1 0x813
#define TYPE_PROBE2 0x814
#define G 2
#define P 0x662c467db14696545ae1a8dd0a00f25d608bd3021de9cd56f79f1ca6d9b4047d


// The data added to the probe by each switch at each hop.
header dh_probe_t {
    bit<256>   public_key;
    // Trere is no need for 8 bytes but header requires multiple of 8 bits.
    bit<8>     flag;  // 0x00 = msg1 / 0x01 = msg2 / 0x02 = msg3 / 0x03 = msg4
}

// We perform one block of AES.
// To perform multiple block using modes like CBC/CTR, etc., simply XOR a counter/IV with value before starting AES.
header aes_inout_t {
    bit<128> value;
}

header pkt_ack_t {
    bit<8> value;
}

struct my_headers_t {
    ethernet_t            ethernet;
    aes_inout_t           aes_inout;
    pkt_ack_t             pkt_ack;
    dh_probe_t[MAX_KEYS]  dh_probe;
}

header aes_meta_t {
    // internal state, 4 rows
    bit<32> r0;
    bit<32> r1;
    bit<32> r2;
    bit<32> r3;
    // temporary accumulator, for XOR-ing the result of many LUTs
    bit<32> t0;
    bit<32> t1;
    bit<32> t2;
    bit<32> t3;

    keys_t  reg_pub_key;
    keys_t  reg_priv_key;
    keys_t  reg_secret_key;

    // expanded keys
    bit<128> expandkey_r0;
    bit<128> expandkey_r1;
    bit<128> expandkey_r2;
    bit<128> expandkey_r3;
    bit<128> expandkey_r4;
    bit<128> expandkey_r5;
    bit<128> expandkey_r6;
    bit<128> expandkey_r7;
    bit<128> expandkey_r8;
    bit<128> expandkey_r9;
    bit<128> expandkey_r10;
    bit<128> expandkey_r11;
    bit<128> expandkey_r12;
    bit<128> expandkey_r13;
    bit<128> expandkey_r14;

    // decrypt expanded keys
    bit<128> inv_expandkey_r0;
    bit<128> inv_expandkey_r1;
    bit<128> inv_expandkey_r2;
    bit<128> inv_expandkey_r3;
    bit<128> inv_expandkey_r4;
    bit<128> inv_expandkey_r5;
    bit<128> inv_expandkey_r6;
    bit<128> inv_expandkey_r7;
    bit<128> inv_expandkey_r8;
    bit<128> inv_expandkey_r9;
    bit<128> inv_expandkey_r10;
    bit<128> inv_expandkey_r11;
    bit<128> inv_expandkey_r12;
    bit<128> inv_expandkey_r13;
    bit<128> inv_expandkey_r14;
}

header dh_meta_t {
    bit<256> secrect;
    bit<256> pu;
}
struct my_metadata_t {
    aes_meta_t aes;
    dh_meta_t[MAX_KEYS] dh;
}

parser MyParser(
    packet_in             packet,
    out   my_headers_t    hdr,
    inout my_metadata_t   meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
           ETHERTYPE_AES_TOY    : parse_pkt_ack;
           TYPE_PROBE           : parse_dh_probe;
           TYPE_PROBE1          : parse_dh_probe;
           TYPE_PROBE2          : parse_dh_probe;
           default              : accept;
        }
    }

    state parse_pkt_ack {
        packet.extract(hdr.pkt_ack);
        transition parse_data;
    }

    state parse_data {
        packet.extract(hdr.aes_inout);
        transition accept;
    }

    state parse_dh_probe {
        packet.extract(hdr.dh_probe.next);
        transition accept;
    }
}

control MyVerifyChecksum(inout my_headers_t hdr, inout my_metadata_t meta) {
    apply { }
}

control MyIngress(
    inout my_headers_t         hdr,
    inout my_metadata_t        meta,
    inout standard_metadata_t  standard_metadata)
{
    bit<256> encryptKey256;
    bit<256> decryptKey256;
    bit<256> secretKey256;
    bit<128> secretKey128;

    bit<2> flag; // 0x3 = encrypt / 0x0 = decrypt / 0x1-0x2 = bypass
    bit<2> keysize; // 0x0 = 128 / 0x1 = 192 / 0x2 = 256

    //  t  ->  previous 4 bytes
    bit<32> t;
    bit<32> t_par0;
    bit<32> t_par1;
    bit<32> t_par2;
    bit<32> t_par3;

    bit<8> word0;
    bit<8> word1;
    bit<8> word2;
    bit<8> word3;

    bit<32> t0_inv;
    bit<32> t1_inv;
    bit<32> t2_inv;
    bit<32> t3_inv;

    bit<32> ti0;
    bit<32> ti1;
    bit<32> ti2;
    bit<32> ti3;

// expand key decrypt
#define get_exp_key(ROUND) action get_exp_key_r##ROUND##(){                     \
                              t0_inv = meta.aes.expandkey_r##ROUND##[127:96];   \
                              t1_inv = meta.aes.expandkey_r##ROUND##[95:64];    \
                              t2_inv = meta.aes.expandkey_r##ROUND##[63:32];    \
                              t3_inv = meta.aes.expandkey_r##ROUND##[31:0];     \
}
get_exp_key(1)
get_exp_key(2)
get_exp_key(3)
get_exp_key(4)
get_exp_key(5)
get_exp_key(6)
get_exp_key(7)
get_exp_key(8)
get_exp_key(9)
get_exp_key(10)
get_exp_key(11)
get_exp_key(12)
get_exp_key(13)

#define get_exp_word_key(ROUND,i,W) action get_exp_word_##i##_r##ROUND##(){     \
                                      word0 = t##W##_inv[31:24];                \
                                      word1 = t##W##_inv[23:16];                \
                                      word2 = t##W##_inv[15:8];                 \
                                      word3 = t##W##_inv[7:0];                  \
}
get_exp_word_key(0,00,0)
get_exp_word_key(0,01,1)
get_exp_word_key(0,02,2)
get_exp_word_key(0,03,3)
get_exp_word_key(1,00,0)
get_exp_word_key(1,01,1)
get_exp_word_key(1,02,2)
get_exp_word_key(1,03,3)
get_exp_word_key(2,00,0)
get_exp_word_key(2,01,1)
get_exp_word_key(2,02,2)
get_exp_word_key(2,03,3)
get_exp_word_key(3,00,0)
get_exp_word_key(3,01,1)
get_exp_word_key(3,02,2)
get_exp_word_key(3,03,3)
get_exp_word_key(4,00,0)
get_exp_word_key(4,01,1)
get_exp_word_key(4,02,2)
get_exp_word_key(4,03,3)
get_exp_word_key(5,00,0)
get_exp_word_key(5,01,1)
get_exp_word_key(5,02,2)
get_exp_word_key(5,03,3)
get_exp_word_key(6,00,0)
get_exp_word_key(6,01,1)
get_exp_word_key(6,02,2)
get_exp_word_key(6,03,3)
get_exp_word_key(7,00,0)
get_exp_word_key(7,01,1)
get_exp_word_key(7,02,2)
get_exp_word_key(7,03,3)
get_exp_word_key(8,00,0)
get_exp_word_key(8,01,1)
get_exp_word_key(8,02,2)
get_exp_word_key(8,03,3)
get_exp_word_key(9,00,0)
get_exp_word_key(9,01,1)
get_exp_word_key(9,02,2)
get_exp_word_key(9,03,3)
get_exp_word_key(10,00,0)
get_exp_word_key(10,01,1)
get_exp_word_key(10,02,2)
get_exp_word_key(10,03,3)
get_exp_word_key(11,00,0)
get_exp_word_key(11,01,1)
get_exp_word_key(11,02,2)
get_exp_word_key(11,03,3)
get_exp_word_key(12,00,0)
get_exp_word_key(12,01,1)
get_exp_word_key(12,02,2)
get_exp_word_key(12,03,3)

#define merge_inv_to(W) action merge_inv_to_ti##W##(bit<32> val){   \
                            ti##W##=val;                            \
}
merge_inv_to(0)
merge_inv_to(1)
merge_inv_to(2)
merge_inv_to(3)

#define expand_inv_round(RC,ROUND,BITS,i) action expand_inv_##i##_r##ROUND##(){     \
        meta.aes.inv_expandkey_r##RC##BITS## = ti0^ti1^ti2^ti3;                     \
}
expand_inv_round(1,0,[127:96],00)
expand_inv_round(1,0,[95:64],01)
expand_inv_round(1,0,[63:32],02)
expand_inv_round(1,0,[31:0],03)
expand_inv_round(2,1,[127:96],00)
expand_inv_round(2,1,[95:64],01)
expand_inv_round(2,1,[63:32],02)
expand_inv_round(2,1,[31:0],03)
expand_inv_round(3,2,[127:96],00)
expand_inv_round(3,2,[95:64],01)
expand_inv_round(3,2,[63:32],02)
expand_inv_round(3,2,[31:0],03)
expand_inv_round(4,3,[127:96],00)
expand_inv_round(4,3,[95:64],01)
expand_inv_round(4,3,[63:32],02)
expand_inv_round(4,3,[31:0],03)
expand_inv_round(5,4,[127:96],00)
expand_inv_round(5,4,[95:64],01)
expand_inv_round(5,4,[63:32],02)
expand_inv_round(5,4,[31:0],03)
expand_inv_round(6,5,[127:96],00)
expand_inv_round(6,5,[95:64],01)
expand_inv_round(6,5,[63:32],02)
expand_inv_round(6,5,[31:0],03)
expand_inv_round(7,6,[127:96],00)
expand_inv_round(7,6,[95:64],01)
expand_inv_round(7,6,[63:32],02)
expand_inv_round(7,6,[31:0],03)
expand_inv_round(8,7,[127:96],00)
expand_inv_round(8,7,[95:64],01)
expand_inv_round(8,7,[63:32],02)
expand_inv_round(8,7,[31:0],03)
expand_inv_round(9,8,[127:96],00)
expand_inv_round(9,8,[95:64],01)
expand_inv_round(9,8,[63:32],02)
expand_inv_round(9,8,[31:0],03)
expand_inv_round(10,9,[127:96],00)
expand_inv_round(10,9,[95:64],01)
expand_inv_round(10,9,[63:32],02)
expand_inv_round(10,9,[31:0],03)
expand_inv_round(11,10,[127:96],00)
expand_inv_round(11,10,[95:64],01)
expand_inv_round(11,10,[63:32],02)
expand_inv_round(11,10,[31:0],03)
expand_inv_round(12,11,[127:96],00)
expand_inv_round(12,11,[95:64],01)
expand_inv_round(12,11,[63:32],02)
expand_inv_round(12,11,[31:0],03)
expand_inv_round(13,12,[127:96],00)
expand_inv_round(13,12,[95:64],01)
expand_inv_round(13,12,[63:32],02)
expand_inv_round(13,12,[31:0],03)
       
// RC current round
// RO old round
// XOR t with the four-byte block bytes before the new expanded key
// This becomes the next four bytes in the expanded key
#define expand_02_round(RO,RC,ROUND) action expand_02_r##ROUND##(){                            \
        t = meta.aes.expandkey_r##RC##[127:96];                                                \
        meta.aes.expandkey_r##RC##[95:88]    = meta.aes.expandkey_r##RO##[95:88]^t[31:24];     \
        meta.aes.expandkey_r##RC##[87:80]    = meta.aes.expandkey_r##RO##[87:80]^t[23:16];     \
        meta.aes.expandkey_r##RC##[79:72]    = meta.aes.expandkey_r##RO##[79:72]^t[15:8];      \
        meta.aes.expandkey_r##RC##[71:64]    = meta.aes.expandkey_r##RO##[71:64]^t[7:0];       \
}
expand_02_round(0,1,0)
expand_02_round(1,2,1)
expand_02_round(2,3,2)
expand_02_round(3,4,3)
expand_02_round(4,5,4)
expand_02_round(5,6,5)
expand_02_round(6,7,6)
expand_02_round(7,8,7)
expand_02_round(8,9,8)
expand_02_round(9,10,9)
expand_02_round(10,11,10)
expand_02_round(11,12,11)
expand_02_round(12,13,12)
expand_02_round(13,14,13)

#define expand_02_192_round(RO,RC,ROUND) action expand_02_192_r##ROUND##(){                  \
        t = meta.aes.expandkey_r##RC##[127:96];                                              \
        meta.aes.expandkey_r##RC##[95:88]    = meta.aes.expandkey_r##RO##[31:24]^t[31:24];   \
        meta.aes.expandkey_r##RC##[87:80]    = meta.aes.expandkey_r##RO##[23:16]^t[23:16];   \
        meta.aes.expandkey_r##RC##[79:72]    = meta.aes.expandkey_r##RO##[15:8]^t[15:8];     \
        meta.aes.expandkey_r##RC##[71:64]    = meta.aes.expandkey_r##RO##[7:0]^t[7:0];       \
}
expand_02_192_round(0,1,0)
expand_02_192_round(0,2,1)
expand_02_192_round(1,3,2)
expand_02_192_round(2,4,3)
expand_02_192_round(3,5,4)
expand_02_192_round(4,6,5)
expand_02_192_round(5,7,6)
expand_02_192_round(6,8,7)
expand_02_192_round(7,9,8)
expand_02_192_round(8,10,9)
expand_02_192_round(9,11,10)
expand_02_192_round(10,12,11)
expand_02_192_round(11,13,12)
expand_02_192_round(12,14,13)

#define expand_02_256_round(RO,RC,ROUND) action expand_02_256_r##ROUND##(){                    \
        t = meta.aes.expandkey_r##RC##[127:96];                                                \
        meta.aes.expandkey_r##RC##[95:88]    = meta.aes.expandkey_r##RO##[95:88]^t[31:24];     \
        meta.aes.expandkey_r##RC##[87:80]    = meta.aes.expandkey_r##RO##[87:80]^t[23:16];     \
        meta.aes.expandkey_r##RC##[79:72]    = meta.aes.expandkey_r##RO##[79:72]^t[15:8];      \
        meta.aes.expandkey_r##RC##[71:64]    = meta.aes.expandkey_r##RO##[71:64]^t[7:0];       \
}
expand_02_256_round(0,2,1)
expand_02_256_round(1,3,2)
expand_02_256_round(2,4,3)
expand_02_256_round(3,5,4)
expand_02_256_round(4,6,5)
expand_02_256_round(5,7,6)
expand_02_256_round(6,8,7)
expand_02_256_round(7,9,8)
expand_02_256_round(8,10,9)
expand_02_256_round(9,11,10)
expand_02_256_round(10,12,11)
expand_02_256_round(11,13,12)
expand_02_256_round(12,14,13)

#define expand_03_round(RO,RC,ROUND) action expand_03_r##ROUND##(){                            \
        meta.aes.expandkey_r##RC##[63:56]    = meta.aes.expandkey_r##RO##[63:56]^t[31:24];     \
        meta.aes.expandkey_r##RC##[55:48]    = meta.aes.expandkey_r##RO##[55:48]^t[23:16];     \
        meta.aes.expandkey_r##RC##[47:40]    = meta.aes.expandkey_r##RO##[47:40]^t[15:8];      \
        meta.aes.expandkey_r##RC##[39:32]    = meta.aes.expandkey_r##RO##[39:32]^t[7:0];       \
        t = meta.aes.expandkey_r##RC##[63:32];                                                 \
        meta.aes.expandkey_r##RC##[31:24]    = meta.aes.expandkey_r##RO##[31:24]^t[31:24];     \
        meta.aes.expandkey_r##RC##[23:16]    = meta.aes.expandkey_r##RO##[23:16]^t[23:16];     \
        meta.aes.expandkey_r##RC##[15:8]     = meta.aes.expandkey_r##RO##[15:8]^t[15:8];       \
        meta.aes.expandkey_r##RC##[7:0]      = meta.aes.expandkey_r##RO##[7:0]^t[7:0];         \
}
expand_03_round(0,1,0)
expand_03_round(1,2,1)
expand_03_round(2,3,2)
expand_03_round(3,4,3)
expand_03_round(4,5,4)
expand_03_round(5,6,5)
expand_03_round(6,7,6)
expand_03_round(7,8,7)
expand_03_round(8,9,8)
expand_03_round(9,10,9)
expand_03_round(10,11,10)
expand_03_round(11,12,11)
expand_03_round(12,13,12)
expand_03_round(13,14,13)

#define expand_03_192_round(RO,RC,ROUND) action expand_03_192_r##ROUND##(){                      \
        meta.aes.expandkey_r##RC##[63:56]    = meta.aes.expandkey_r##RO##[127:120]^t[31:24];     \
        meta.aes.expandkey_r##RC##[55:48]    = meta.aes.expandkey_r##RO##[119:112]^t[23:16];     \
        meta.aes.expandkey_r##RC##[47:40]    = meta.aes.expandkey_r##RO##[111:104]^t[15:8];      \
        meta.aes.expandkey_r##RC##[39:32]    = meta.aes.expandkey_r##RO##[103:96]^t[7:0];        \
        t = meta.aes.expandkey_r##RC##[63:32];                                                   \
        meta.aes.expandkey_r##RC##[31:24]    = meta.aes.expandkey_r##RO##[95:88]^t[31:24];       \
        meta.aes.expandkey_r##RC##[23:16]    = meta.aes.expandkey_r##RO##[87:80]^t[23:16];       \
        meta.aes.expandkey_r##RC##[15:8]     = meta.aes.expandkey_r##RO##[79:72]^t[15:8];        \
        meta.aes.expandkey_r##RC##[7:0]      = meta.aes.expandkey_r##RO##[71:64]^t[7:0];         \
}
expand_03_192_round(0,1,0)
expand_03_192_round(1,2,1)
expand_03_192_round(2,3,2)
expand_03_192_round(3,4,3)
expand_03_192_round(4,5,4)
expand_03_192_round(5,6,5)
expand_03_192_round(6,7,6)
expand_03_192_round(7,8,7)
expand_03_192_round(8,9,8)
expand_03_192_round(9,10,9)
expand_03_192_round(10,11,10)
expand_03_192_round(11,12,11)
expand_03_192_round(12,13,12)
expand_03_192_round(13,14,13)

#define expand_03_256_round(RO,RC,ROUND) action expand_03_256_r##ROUND##(){                    \
        meta.aes.expandkey_r##RC##[63:56]    = meta.aes.expandkey_r##RO##[63:56]^t[31:24];     \
        meta.aes.expandkey_r##RC##[55:48]    = meta.aes.expandkey_r##RO##[55:48]^t[23:16];     \
        meta.aes.expandkey_r##RC##[47:40]    = meta.aes.expandkey_r##RO##[47:40]^t[15:8];      \
        meta.aes.expandkey_r##RC##[39:32]    = meta.aes.expandkey_r##RO##[39:32]^t[7:0];       \
        t = meta.aes.expandkey_r##RC##[63:32];                                                 \
        meta.aes.expandkey_r##RC##[31:24]    = meta.aes.expandkey_r##RO##[31:24]^t[31:24];     \
        meta.aes.expandkey_r##RC##[23:16]    = meta.aes.expandkey_r##RO##[23:16]^t[23:16];     \
        meta.aes.expandkey_r##RC##[15:8]     = meta.aes.expandkey_r##RO##[15:8]^t[15:8];       \
        meta.aes.expandkey_r##RC##[7:0]      = meta.aes.expandkey_r##RO##[7:0]^t[7:0];         \
}
expand_03_256_round(0,2,1)
expand_03_256_round(1,3,2)
expand_03_256_round(2,4,3)
expand_03_256_round(3,5,4)
expand_03_256_round(4,6,5)
expand_03_256_round(5,7,6)
expand_03_256_round(6,8,7)
expand_03_256_round(7,9,8)
expand_03_256_round(8,10,9)
expand_03_256_round(9,11,10)
expand_03_256_round(10,12,11)
expand_03_256_round(11,13,12)
expand_03_256_round(12,14,13)

#define expand_set_t_02_round(RC,ROUND) action expand_set_t_02_r##ROUND##(){          \
                                            t = meta.aes.expandkey_r##RC##[95:64];    \
                                            word0 = t[23:16];                         \
                                            word1 = t[15:8];                          \
                                            word2 = t[7:0];                           \
                                            word3 = t[31:24];                         \
}
expand_set_t_02_round(1,0)
expand_set_t_02_round(2,1)
expand_set_t_02_round(3,2)
expand_set_t_02_round(4,3)
expand_set_t_02_round(5,4)
expand_set_t_02_round(6,5)
expand_set_t_02_round(7,6)
expand_set_t_02_round(8,7)
expand_set_t_02_round(9,8)
expand_set_t_02_round(10,9)
expand_set_t_02_round(11,10)
expand_set_t_02_round(12,11)
expand_set_t_02_round(13,12)
expand_set_t_02_round(14,13)


// Assign the previous 4 bytes to the temporary value t
// Rotate the 32-bit t 8 bits to the left and save in wx
#define expand_set_t_01_round(RO,ROUND) action expand_set_t_01_r##ROUND##(){                    \
                                            t[31:24] = meta.aes.expandkey_r##ROUND##[31:24];    \
                                            t[23:16] = meta.aes.expandkey_r##ROUND##[23:16];    \
                                            t[15:8] = meta.aes.expandkey_r##ROUND##[15:8];      \
                                            t[7:0] = meta.aes.expandkey_r##ROUND##[7:0];        \
                                            word0 = t[23:16];                                   \
                                            word1 = t[15:8];                                    \
                                            word2 = t[7:0];                                     \
                                            word3 = t[31:24];                                   \
}
expand_set_t_01_round(0,0)
expand_set_t_01_round(1,1)
expand_set_t_01_round(2,2)
expand_set_t_01_round(3,3)
expand_set_t_01_round(4,4)
expand_set_t_01_round(5,5)
expand_set_t_01_round(6,6)
expand_set_t_01_round(7,7)
expand_set_t_01_round(8,8)
expand_set_t_01_round(9,9)
expand_set_t_01_round(10,10)
expand_set_t_01_round(11,11)
expand_set_t_01_round(12,12)
expand_set_t_01_round(13,13)

// First XOR after sbox
#define expand_01_round(RO,RC,ROUND) action expand_01_r##ROUND##(){                            \
        meta.aes.expandkey_r##RC##[127:120]  = meta.aes.expandkey_r##RO##[127:120]^t[31:24];   \
        meta.aes.expandkey_r##RC##[119:112]  = meta.aes.expandkey_r##RO##[119:112]^t[23:16];   \
        meta.aes.expandkey_r##RC##[111:104]  = meta.aes.expandkey_r##RO##[111:104]^t[15:8];    \
        meta.aes.expandkey_r##RC##[103:96]   = meta.aes.expandkey_r##RO##[103:96]^t[7:0];      \
}
expand_01_round(0,1,0)
expand_01_round(1,2,1)
expand_01_round(2,3,2)
expand_01_round(3,4,3)
expand_01_round(4,5,4)
expand_01_round(5,6,5)
expand_01_round(6,7,6)
expand_01_round(7,8,7)
expand_01_round(8,9,8)
expand_01_round(9,10,9)
expand_01_round(10,11,10)
expand_01_round(11,12,11)
expand_01_round(12,13,12)
expand_01_round(13,14,13)

#define expand_01_192_round(RO,RC,ROUND) action expand_01_192_r##ROUND##(){                  \
        meta.aes.expandkey_r##RC##[127:120]  = meta.aes.expandkey_r##RO##[63:56]^t[31:24];   \
        meta.aes.expandkey_r##RC##[119:112]  = meta.aes.expandkey_r##RO##[55:48]^t[23:16];   \
        meta.aes.expandkey_r##RC##[111:104]  = meta.aes.expandkey_r##RO##[47:40]^t[15:8];    \
        meta.aes.expandkey_r##RC##[103:96]   = meta.aes.expandkey_r##RO##[39:32]^t[7:0];     \
}
expand_01_192_round(0,2,1)
expand_01_192_round(1,3,2)
expand_01_192_round(2,4,3)
expand_01_192_round(3,5,4)
expand_01_192_round(4,6,5)
expand_01_192_round(5,7,6)
expand_01_192_round(6,8,7)
expand_01_192_round(7,9,8)
expand_01_192_round(8,10,9)
expand_01_192_round(9,11,10)
expand_01_192_round(10,12,11)
expand_01_192_round(11,13,12)
expand_01_192_round(12,14,13)

#define expand_01_256_round(RO,RC,ROUND) action expand_01_256_r##ROUND##(){                     \
        meta.aes.expandkey_r##RC##[127:120]  = meta.aes.expandkey_r##RO##[127:120]^t[31:24];    \
        meta.aes.expandkey_r##RC##[119:112]  = meta.aes.expandkey_r##RO##[119:112]^t[23:16];    \
        meta.aes.expandkey_r##RC##[111:104]  = meta.aes.expandkey_r##RO##[111:104]^t[15:8];     \
        meta.aes.expandkey_r##RC##[103:96]   = meta.aes.expandkey_r##RO##[103:96]^t[7:0];       \
}
expand_01_256_round(0,2,1)
expand_01_256_round(1,3,2)
expand_01_256_round(2,4,3)
expand_01_256_round(3,5,4)
expand_01_256_round(4,6,5)
expand_01_256_round(5,7,6)
expand_01_256_round(6,8,7)
expand_01_256_round(7,9,8)
expand_01_256_round(8,10,9)
expand_01_256_round(9,11,10)
expand_01_256_round(10,12,11)
expand_01_256_round(11,13,12)
expand_01_256_round(12,14,13)

// apply S-Box substitution on all 4 parts of the 32-bit 
#define merge_sbox_to(W) action merge_sbox_to_w##W##(bit<8> val){   \
                            word##W##=val;                          \
}
merge_sbox_to(0)
merge_sbox_to(1)
merge_sbox_to(2)
merge_sbox_to(3)

#define merge_sbox_to_t(W,BITS) action merge_sbox_to_t##W##(bit<8> val){    \
                                    t##BITS##=val;                          \
}
merge_sbox_to_t(0,[31:24])
merge_sbox_to_t(1,[23:16])
merge_sbox_to_t(2,[15:8])
merge_sbox_to_t(3,[7:0])

// apply rcon substitution and XOR the output to the first part (leftmost) only
#define merge_rcon_to(ROUND,W,rcon_val) action merge_rcon_to_w##W##_r##ROUND##(){   \
                                            word##W##=word##W##^##rcon_val##;       \
                                            t[31:24] = word0;                       \
                                            t[23:16] = word1;                       \
                                            t[15:8] = word2;                        \
                                            t[7:0] = word3;                         \
}
merge_rcon_to(0,0,0x01)
merge_rcon_to(1,0,0x02)
merge_rcon_to(2,0,0x04)
merge_rcon_to(3,0,0x08)
merge_rcon_to(4,0,0x10)
merge_rcon_to(5,0,0x20)
merge_rcon_to(6,0,0x40)
merge_rcon_to(7,0,0x80)
merge_rcon_to(8,0,0x1b)
merge_rcon_to(9,0,0x36)
merge_rcon_to(10,0,0x6c)
merge_rcon_to(11,0,0xd8)
merge_rcon_to(12,0,0xab)
merge_rcon_to(13,0,0x4d)

#define TABLE_EXPAND(NAME,READ,WRITE) table NAME {              \
                                        key = {READ:exact;}     \
                                        actions = {WRITE;}      \
}

#define SBOXVALUE00(ROUND) TABLE_EXPAND(aes_sbox_00_r##ROUND, word0, merge_sbox_to_w0)
#define SBOXVALUE01(ROUND) TABLE_EXPAND(aes_sbox_01_r##ROUND, word1, merge_sbox_to_w1)
#define SBOXVALUE02(ROUND) TABLE_EXPAND(aes_sbox_02_r##ROUND, word2, merge_sbox_to_w2)
#define SBOXVALUE03(ROUND) TABLE_EXPAND(aes_sbox_03_r##ROUND, word3, merge_sbox_to_w3)

#define SBOXVALUE10(ROUND) TABLE_EXPAND(aes_sbox_10_r##ROUND, word0, merge_sbox_to_w0)
#define SBOXVALUE11(ROUND) TABLE_EXPAND(aes_sbox_11_r##ROUND, word1, merge_sbox_to_w1)
#define SBOXVALUE12(ROUND) TABLE_EXPAND(aes_sbox_12_r##ROUND, word2, merge_sbox_to_w2)
#define SBOXVALUE13(ROUND) TABLE_EXPAND(aes_sbox_13_r##ROUND, word3, merge_sbox_to_w3)

#define SBOXVALUE20(ROUND) TABLE_EXPAND(aes_sbox_20_r##ROUND, word0, merge_sbox_to_w0)
#define SBOXVALUE21(ROUND) TABLE_EXPAND(aes_sbox_21_r##ROUND, word1, merge_sbox_to_w1)
#define SBOXVALUE22(ROUND) TABLE_EXPAND(aes_sbox_22_r##ROUND, word2, merge_sbox_to_w2)
#define SBOXVALUE23(ROUND) TABLE_EXPAND(aes_sbox_23_r##ROUND, word3, merge_sbox_to_w3)

#define SBOXVALUE30(ROUND) TABLE_EXPAND(aes_sbox_30_r##ROUND, word0, merge_sbox_to_w0)
#define SBOXVALUE31(ROUND) TABLE_EXPAND(aes_sbox_31_r##ROUND, word1, merge_sbox_to_w1)
#define SBOXVALUE32(ROUND) TABLE_EXPAND(aes_sbox_32_r##ROUND, word2, merge_sbox_to_w2)
#define SBOXVALUE33(ROUND) TABLE_EXPAND(aes_sbox_33_r##ROUND, word3, merge_sbox_to_w3)

#define SBOXVALUE40(ROUND) TABLE_EXPAND(aes_sbox_40_r##ROUND, word0, merge_sbox_to_w0)
#define SBOXVALUE41(ROUND) TABLE_EXPAND(aes_sbox_41_r##ROUND, word1, merge_sbox_to_w1)
#define SBOXVALUE42(ROUND) TABLE_EXPAND(aes_sbox_42_r##ROUND, word2, merge_sbox_to_w2)
#define SBOXVALUE43(ROUND) TABLE_EXPAND(aes_sbox_43_r##ROUND, word3, merge_sbox_to_w3)

#define SBOXVALUE50(ROUND) TABLE_EXPAND(aes_sbox_50_r##ROUND, t[31:24], merge_sbox_to_t0)
#define SBOXVALUE51(ROUND) TABLE_EXPAND(aes_sbox_51_r##ROUND, t[23:16], merge_sbox_to_t1)
#define SBOXVALUE52(ROUND) TABLE_EXPAND(aes_sbox_52_r##ROUND, t[15:8], merge_sbox_to_t2)
#define SBOXVALUE53(ROUND) TABLE_EXPAND(aes_sbox_53_r##ROUND, t[7:0], merge_sbox_to_t3)

#define LUT_EXP_00(ROUND) TABLE_EXPAND(aes_sbox_lut_exp_00_r##ROUND, word0, merge_inv_to_ti0)
#define LUT_EXP_01(ROUND) TABLE_EXPAND(aes_sbox_lut_exp_01_r##ROUND, word1, merge_inv_to_ti1)
#define LUT_EXP_02(ROUND) TABLE_EXPAND(aes_sbox_lut_exp_02_r##ROUND, word2, merge_inv_to_ti2)
#define LUT_EXP_03(ROUND) TABLE_EXPAND(aes_sbox_lut_exp_03_r##ROUND, word3, merge_inv_to_ti3)

#define LUT_EXP_10(ROUND) TABLE_EXPAND(aes_sbox_lut_exp_10_r##ROUND, word0, merge_inv_to_ti0)
#define LUT_EXP_11(ROUND) TABLE_EXPAND(aes_sbox_lut_exp_11_r##ROUND, word1, merge_inv_to_ti1)
#define LUT_EXP_12(ROUND) TABLE_EXPAND(aes_sbox_lut_exp_12_r##ROUND, word2, merge_inv_to_ti2)
#define LUT_EXP_13(ROUND) TABLE_EXPAND(aes_sbox_lut_exp_13_r##ROUND, word3, merge_inv_to_ti3)

#define LUT_EXP_20(ROUND) TABLE_EXPAND(aes_sbox_lut_exp_20_r##ROUND, word0, merge_inv_to_ti0)
#define LUT_EXP_21(ROUND) TABLE_EXPAND(aes_sbox_lut_exp_21_r##ROUND, word1, merge_inv_to_ti1)
#define LUT_EXP_22(ROUND) TABLE_EXPAND(aes_sbox_lut_exp_22_r##ROUND, word2, merge_inv_to_ti2)
#define LUT_EXP_23(ROUND) TABLE_EXPAND(aes_sbox_lut_exp_23_r##ROUND, word3, merge_inv_to_ti3)
    
#define LUT_EXP_30(ROUND) TABLE_EXPAND(aes_sbox_lut_exp_30_r##ROUND, word0, merge_inv_to_ti0)
#define LUT_EXP_31(ROUND) TABLE_EXPAND(aes_sbox_lut_exp_31_r##ROUND, word1, merge_inv_to_ti1)
#define LUT_EXP_32(ROUND) TABLE_EXPAND(aes_sbox_lut_exp_32_r##ROUND, word2, merge_inv_to_ti2)
#define LUT_EXP_33(ROUND) TABLE_EXPAND(aes_sbox_lut_exp_33_r##ROUND, word3, merge_inv_to_ti3)
    
#define GENERATE_ALL_TABLE_SBOX(ROUND)  SBOXVALUE00(ROUND) SBOXVALUE01(ROUND) SBOXVALUE02(ROUND) SBOXVALUE03(ROUND) \
                                        SBOXVALUE10(ROUND) SBOXVALUE11(ROUND) SBOXVALUE12(ROUND) SBOXVALUE13(ROUND) \
                                        SBOXVALUE20(ROUND) SBOXVALUE21(ROUND) SBOXVALUE22(ROUND) SBOXVALUE23(ROUND) \
                                        SBOXVALUE30(ROUND) SBOXVALUE31(ROUND) SBOXVALUE32(ROUND) SBOXVALUE33(ROUND) \
                                        SBOXVALUE40(ROUND) SBOXVALUE41(ROUND) SBOXVALUE42(ROUND) SBOXVALUE43(ROUND) 
GENERATE_ALL_TABLE_SBOX(0)
GENERATE_ALL_TABLE_SBOX(1)
GENERATE_ALL_TABLE_SBOX(2)
GENERATE_ALL_TABLE_SBOX(3)
GENERATE_ALL_TABLE_SBOX(4)
GENERATE_ALL_TABLE_SBOX(5)
GENERATE_ALL_TABLE_SBOX(6)
GENERATE_ALL_TABLE_SBOX(7)
GENERATE_ALL_TABLE_SBOX(8)
GENERATE_ALL_TABLE_SBOX(9)
GENERATE_ALL_TABLE_SBOX(10)
GENERATE_ALL_TABLE_SBOX(11)


#define GENERATE_ALL_TABLE_LAST(ROUND)  SBOXVALUE10(ROUND) SBOXVALUE11(ROUND) SBOXVALUE12(ROUND) SBOXVALUE13(ROUND) \
                                        SBOXVALUE20(ROUND) SBOXVALUE21(ROUND) SBOXVALUE22(ROUND) SBOXVALUE23(ROUND) \
                                        SBOXVALUE30(ROUND) SBOXVALUE31(ROUND) SBOXVALUE32(ROUND) SBOXVALUE33(ROUND) \
                                        SBOXVALUE40(ROUND) SBOXVALUE41(ROUND) SBOXVALUE42(ROUND) SBOXVALUE43(ROUND) 
GENERATE_ALL_TABLE_LAST(12)

#define GENERATE_TABLE_SBOX_256(ROUND)  SBOXVALUE50(ROUND) SBOXVALUE51(ROUND) SBOXVALUE52(ROUND) SBOXVALUE53(ROUND) 
GENERATE_TABLE_SBOX_256(0)
GENERATE_TABLE_SBOX_256(1)
GENERATE_TABLE_SBOX_256(2)
GENERATE_TABLE_SBOX_256(3)
GENERATE_TABLE_SBOX_256(4)
GENERATE_TABLE_SBOX_256(5)

#define GENERATE_ALL_UNTABLE_LUT_EXPAND(ROUND)  LUT_EXP_00(ROUND) LUT_EXP_01(ROUND) LUT_EXP_02(ROUND) LUT_EXP_03(ROUND) \
                                                LUT_EXP_10(ROUND) LUT_EXP_11(ROUND) LUT_EXP_12(ROUND) LUT_EXP_13(ROUND) \
                                                LUT_EXP_20(ROUND) LUT_EXP_21(ROUND) LUT_EXP_22(ROUND) LUT_EXP_23(ROUND) \
                                                LUT_EXP_30(ROUND) LUT_EXP_31(ROUND) LUT_EXP_32(ROUND) LUT_EXP_33(ROUND)
GENERATE_ALL_UNTABLE_LUT_EXPAND(0)
GENERATE_ALL_UNTABLE_LUT_EXPAND(1)
GENERATE_ALL_UNTABLE_LUT_EXPAND(2)
GENERATE_ALL_UNTABLE_LUT_EXPAND(3)
GENERATE_ALL_UNTABLE_LUT_EXPAND(4)
GENERATE_ALL_UNTABLE_LUT_EXPAND(5)
GENERATE_ALL_UNTABLE_LUT_EXPAND(6)
GENERATE_ALL_UNTABLE_LUT_EXPAND(7)
GENERATE_ALL_UNTABLE_LUT_EXPAND(8)
GENERATE_ALL_UNTABLE_LUT_EXPAND(9)
GENERATE_ALL_UNTABLE_LUT_EXPAND(10)
GENERATE_ALL_UNTABLE_LUT_EXPAND(11)
GENERATE_ALL_UNTABLE_LUT_EXPAND(12)

    action breakMsg() {
        standard_metadata.egress_spec = 99;
    }

    //action return_msg(){
    //     standard_metadata.egress_spec = standard_metadata.ingress_port;
    //}

    action reflect() {
        //set the src mac address as the previous dst, this is not correct right?
        macAddr_t srcAddr;
        srcAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        //set the destination mac address that we got from the match in the table
        hdr.ethernet.dstAddr = srcAddr;
        //set the output port that we also get from the table
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action l2_fwd() {
        macAddr_t srcAddr;
        srcAddr = hdr.ethernet.srcAddr;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = srcAddr;
        //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action proceed_dh() {
        hdr.aes_inout.setInvalid();
        hdr.pkt_ack.setInvalid();
        hdr.dh_probe[0].setValid();
    }

    action proceed_data() {
        hdr.pkt_ack.setValid();
        hdr.aes_inout.setValid();
        hdr.dh_probe[0].setInvalid();
    }

    // Compute DH
    action compute_secret_dh_ph1() {
        keys_t A;
        register_priv_keys.read(A, 0);

        register_secret_keys.write(0, (hdr.dh_probe[0].public_key & A) ^ P);
    }

    // Compute DH
    action compute_secret_dh_ph2() {
        keys_t A;
        register_priv_keys.read(A, 0);

        keys_t Ka;
        register_pub_keys.read(Ka, 0);
        register_secret_keys.write(0, (Ka & A) ^ P);
    }

    // Write the pub key into the header
    action write_pubKey() {
        hdr.dh_probe[0].public_key = meta.dh[0].pu;
        //hdr.dh_probe[0].setValid();
    }

    action _drop() {
        mark_to_drop(standard_metadata);
    }

    // Read clear/ciphered text into the payload
    action read_payload(){
        meta.aes.t0 = hdr.aes_inout.value[127:96];
        meta.aes.t1 = hdr.aes_inout.value[95:64];
        meta.aes.t2 = hdr.aes_inout.value[63:32];
        meta.aes.t3 = hdr.aes_inout.value[31:0];
    }

    // Write clear/ciphered text into the payload
    action write_payload(){
        hdr.aes_inout.value[127:96] = meta.aes.r0;
        hdr.aes_inout.value[95:64] = meta.aes.r1;
        hdr.aes_inout.value[63:32] = meta.aes.r2;
        hdr.aes_inout.value[31:0] = meta.aes.r3;
    }

    // Meta xored with the expanded key
    action mask_key(bit<128> key128){
        meta.aes.r0 = meta.aes.t0^key128[127:96];
        meta.aes.r1 = meta.aes.t1^key128[95:64];
        meta.aes.r2 = meta.aes.t2^key128[63:32];
        meta.aes.r3 = meta.aes.t3^key128[31:0];
    }

    action new_round() {
        // Could be skipped, if we use better renaming and read key first.
        // We do this for the sake of code tidyness. More efficient implementation
        // possible, using fewer hardware stages.
        meta.aes.t0=0;  meta.aes.t1=0;  meta.aes.t2=0;  meta.aes.t3=0;
    }

    action set_egress_spec(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action set_aes_key(bit<256> key_256) {
        meta.aes.expandkey_r0 = key_256[255:128];
        meta.aes.expandkey_r1 = key_256[127:0];
        meta.aes.inv_expandkey_r0 = key_256[255:128];
    }

    table forward {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_egress_spec;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

// Macros for defining actions, XOR value from LUT to accummulator variable
#define unmerge_to(T) action unmerge_to_t##T##(bit<32> val){    \
                        meta.aes.t##T##=meta.aes.t##T##^val;    \
}
unmerge_to(0)
unmerge_to(1)
unmerge_to(2)
unmerge_to(3)

// XOR value from LUT to a slice of accummulator variable
#define unmerge_to_partial(T,SLICE,SLICE_BITS)  action unmerge_to_t##T##_slice##SLICE##(bit<8> val){    \
    meta.aes.t##T##SLICE_BITS##=meta.aes.t##T##SLICE_BITS##^val;                                        \
}
unmerge_to_partial(0,0,[31:24])
unmerge_to_partial(0,1,[23:16])
unmerge_to_partial(0,2,[15: 8])
unmerge_to_partial(0,3,[ 7: 0])
unmerge_to_partial(1,0,[31:24])
unmerge_to_partial(1,1,[23:16])
unmerge_to_partial(1,2,[15: 8])
unmerge_to_partial(1,3,[ 7: 0])
unmerge_to_partial(2,0,[31:24])
unmerge_to_partial(2,1,[23:16])
unmerge_to_partial(2,2,[15: 8])
unmerge_to_partial(2,3,[ 7: 0])
unmerge_to_partial(3,0,[31:24])
unmerge_to_partial(3,1,[23:16])
unmerge_to_partial(3,2,[15: 8])
unmerge_to_partial(3,3,[ 7: 0])

// Macros for defining actions, XOR value from LUT to accummulator variable
#define merge_to(T) action merge_to_t##T##(bit<32> val){        \
                        meta.aes.t##T##=meta.aes.t##T##^val;    \
}
merge_to(0)
merge_to(1)
merge_to(2)
merge_to(3)

// XOR value from LUT to a slice of accummulator variable
#define merge_to_partial(T,SLICE,SLICE_BITS)  action merge_to_t##T##_slice##SLICE##(bit<8> val){    \
    meta.aes.t##T##SLICE_BITS##=meta.aes.t##T##SLICE_BITS##^val;                                    \
}
merge_to_partial(0,0,[31:24])
merge_to_partial(0,1,[23:16])
merge_to_partial(0,2,[15: 8])
merge_to_partial(0,3,[ 7: 0])
merge_to_partial(1,0,[31:24])
merge_to_partial(1,1,[23:16])
merge_to_partial(1,2,[15: 8])
merge_to_partial(1,3,[ 7: 0])
merge_to_partial(2,0,[31:24])
merge_to_partial(2,1,[23:16])
merge_to_partial(2,2,[15: 8])
merge_to_partial(2,3,[ 7: 0])
merge_to_partial(3,0,[31:24])
merge_to_partial(3,1,[23:16])
merge_to_partial(3,2,[15: 8])
merge_to_partial(3,3,[ 7: 0])


// Macros for defining lookup tables, which is match-action table that XOR the value into accumulator variable
#define UNTABLE_LUT(NAME,READ,WRITE) table NAME {               \
                                        key = {READ:exact;}     \
                                        actions = {WRITE;}      \
}

#define LUT100(ROUND)   UNTABLE_LUT(aes_invsbox_lut_00_r##ROUND, meta.aes.r0[31:24], unmerge_to_t0)
#define LUT101(ROUND)   UNTABLE_LUT(aes_invsbox_lut_01_r##ROUND, meta.aes.r3[23:16], unmerge_to_t0)
#define LUT102(ROUND)   UNTABLE_LUT(aes_invsbox_lut_02_r##ROUND, meta.aes.r2[15: 8], unmerge_to_t0)
#define LUT103(ROUND)   UNTABLE_LUT(aes_invsbox_lut_03_r##ROUND, meta.aes.r1[7 : 0], unmerge_to_t0)

#define LUT110(ROUND)   UNTABLE_LUT(aes_invsbox_lut_10_r##ROUND, meta.aes.r1[31:24], unmerge_to_t1)
#define LUT111(ROUND)   UNTABLE_LUT(aes_invsbox_lut_11_r##ROUND, meta.aes.r0[23:16], unmerge_to_t1)
#define LUT112(ROUND)   UNTABLE_LUT(aes_invsbox_lut_12_r##ROUND, meta.aes.r3[15: 8], unmerge_to_t1)
#define LUT113(ROUND)   UNTABLE_LUT(aes_invsbox_lut_13_r##ROUND, meta.aes.r2[7 : 0], unmerge_to_t1)

#define LUT120(ROUND)   UNTABLE_LUT(aes_invsbox_lut_20_r##ROUND, meta.aes.r2[31:24], unmerge_to_t2)
#define LUT121(ROUND)   UNTABLE_LUT(aes_invsbox_lut_21_r##ROUND, meta.aes.r1[23:16], unmerge_to_t2)
#define LUT122(ROUND)   UNTABLE_LUT(aes_invsbox_lut_22_r##ROUND, meta.aes.r0[15: 8], unmerge_to_t2)
#define LUT123(ROUND)   UNTABLE_LUT(aes_invsbox_lut_23_r##ROUND, meta.aes.r3[7 : 0], unmerge_to_t2)

#define LUT130(ROUND)   UNTABLE_LUT(aes_invsbox_lut_30_r##ROUND, meta.aes.r3[31:24], unmerge_to_t3)
#define LUT131(ROUND)   UNTABLE_LUT(aes_invsbox_lut_31_r##ROUND, meta.aes.r2[23:16], unmerge_to_t3)
#define LUT132(ROUND)   UNTABLE_LUT(aes_invsbox_lut_32_r##ROUND, meta.aes.r1[15: 8], unmerge_to_t3)
#define LUT133(ROUND)   UNTABLE_LUT(aes_invsbox_lut_33_r##ROUND, meta.aes.r0[7 : 0], unmerge_to_t3)


// We need one copy of all tables for each round. Otherwise, there's dependency issue...
#define GENERATE_ALL_UNTABLE_LUT(ROUND) LUT100(ROUND) LUT101(ROUND) LUT102(ROUND) LUT103(ROUND) \
                                        LUT110(ROUND) LUT111(ROUND) LUT112(ROUND) LUT113(ROUND) \
                                        LUT120(ROUND) LUT121(ROUND) LUT122(ROUND) LUT123(ROUND) \
                                        LUT130(ROUND) LUT131(ROUND) LUT132(ROUND) LUT133(ROUND)
GENERATE_ALL_UNTABLE_LUT(13)
GENERATE_ALL_UNTABLE_LUT(12)
GENERATE_ALL_UNTABLE_LUT(11)
GENERATE_ALL_UNTABLE_LUT(10)
GENERATE_ALL_UNTABLE_LUT(9)
GENERATE_ALL_UNTABLE_LUT(8)
GENERATE_ALL_UNTABLE_LUT(7)
GENERATE_ALL_UNTABLE_LUT(6)
GENERATE_ALL_UNTABLE_LUT(5)
GENERATE_ALL_UNTABLE_LUT(4)
GENERATE_ALL_UNTABLE_LUT(3)
GENERATE_ALL_UNTABLE_LUT(2)
GENERATE_ALL_UNTABLE_LUT(1)

// Only round 1-9 requires mixcolumns. round 10 is different:
// LAST round is special, use SBOX directly as LUT

UNTABLE_LUT(aes_invsbox_lut_00_rLAST, meta.aes.r0[31:24], unmerge_to_t0_slice0)
UNTABLE_LUT(aes_invsbox_lut_01_rLAST, meta.aes.r3[23:16], unmerge_to_t0_slice1)
UNTABLE_LUT(aes_invsbox_lut_02_rLAST, meta.aes.r2[15: 8], unmerge_to_t0_slice2)
UNTABLE_LUT(aes_invsbox_lut_03_rLAST, meta.aes.r1[7 : 0], unmerge_to_t0_slice3)

UNTABLE_LUT(aes_invsbox_lut_10_rLAST, meta.aes.r1[31:24], unmerge_to_t1_slice0)
UNTABLE_LUT(aes_invsbox_lut_11_rLAST, meta.aes.r0[23:16], unmerge_to_t1_slice1)
UNTABLE_LUT(aes_invsbox_lut_12_rLAST, meta.aes.r3[15: 8], unmerge_to_t1_slice2)
UNTABLE_LUT(aes_invsbox_lut_13_rLAST, meta.aes.r2[7 : 0], unmerge_to_t1_slice3)

UNTABLE_LUT(aes_invsbox_lut_20_rLAST, meta.aes.r2[31:24], unmerge_to_t2_slice0)
UNTABLE_LUT(aes_invsbox_lut_21_rLAST, meta.aes.r1[23:16], unmerge_to_t2_slice1)
UNTABLE_LUT(aes_invsbox_lut_22_rLAST, meta.aes.r0[15: 8], unmerge_to_t2_slice2)
UNTABLE_LUT(aes_invsbox_lut_23_rLAST, meta.aes.r3[7 : 0], unmerge_to_t2_slice3)

UNTABLE_LUT(aes_invsbox_lut_30_rLAST, meta.aes.r3[31:24], unmerge_to_t3_slice0)
UNTABLE_LUT(aes_invsbox_lut_31_rLAST, meta.aes.r2[23:16], unmerge_to_t3_slice1)
UNTABLE_LUT(aes_invsbox_lut_32_rLAST, meta.aes.r1[15: 8], unmerge_to_t3_slice2)
UNTABLE_LUT(aes_invsbox_lut_33_rLAST, meta.aes.r0[7 : 0], unmerge_to_t3_slice3)


#define UNAP(ROUND,i) aes_invsbox_lut_##i##_r##ROUND##.apply();
#define APPLY_ALL_UNTABLE_LUT(ROUND)    UNAP(ROUND,00) UNAP(ROUND,01) UNAP(ROUND,02) UNAP(ROUND,03) \
                                        UNAP(ROUND,10) UNAP(ROUND,11) UNAP(ROUND,12) UNAP(ROUND,13) \
                                        UNAP(ROUND,20) UNAP(ROUND,21) UNAP(ROUND,22) UNAP(ROUND,23) \
                                        UNAP(ROUND,30) UNAP(ROUND,31) UNAP(ROUND,32) UNAP(ROUND,33)

// Macros for defining lookup tables, which is match-action table that XOR the value into accumulator variable
#define TABLE_LUT(NAME,READ,WRITE) table NAME {         \
                                    key= {READ:exact;}  \
                                    actions = {WRITE;}  \
}

#define LUT00(ROUND)    TABLE_LUT(aes_sbox_lut_00_r##ROUND, meta.aes.r0[31:24], merge_to_t0)
#define LUT01(ROUND)    TABLE_LUT(aes_sbox_lut_01_r##ROUND, meta.aes.r1[23:16], merge_to_t0)
#define LUT02(ROUND)    TABLE_LUT(aes_sbox_lut_02_r##ROUND, meta.aes.r2[15: 8], merge_to_t0)
#define LUT03(ROUND)    TABLE_LUT(aes_sbox_lut_03_r##ROUND, meta.aes.r3[7 : 0], merge_to_t0)

#define LUT10(ROUND)    TABLE_LUT(aes_sbox_lut_10_r##ROUND, meta.aes.r1[31:24], merge_to_t1)
#define LUT11(ROUND)    TABLE_LUT(aes_sbox_lut_11_r##ROUND, meta.aes.r2[23:16], merge_to_t1)
#define LUT12(ROUND)    TABLE_LUT(aes_sbox_lut_12_r##ROUND, meta.aes.r3[15: 8], merge_to_t1)
#define LUT13(ROUND)    TABLE_LUT(aes_sbox_lut_13_r##ROUND, meta.aes.r0[7 : 0], merge_to_t1)

#define LUT20(ROUND)    TABLE_LUT(aes_sbox_lut_20_r##ROUND, meta.aes.r2[31:24], merge_to_t2)
#define LUT21(ROUND)    TABLE_LUT(aes_sbox_lut_21_r##ROUND, meta.aes.r3[23:16], merge_to_t2)
#define LUT22(ROUND)    TABLE_LUT(aes_sbox_lut_22_r##ROUND, meta.aes.r0[15: 8], merge_to_t2)
#define LUT23(ROUND)    TABLE_LUT(aes_sbox_lut_23_r##ROUND, meta.aes.r1[7 : 0], merge_to_t2)

#define LUT30(ROUND)    TABLE_LUT(aes_sbox_lut_30_r##ROUND, meta.aes.r3[31:24], merge_to_t3)
#define LUT31(ROUND)    TABLE_LUT(aes_sbox_lut_31_r##ROUND, meta.aes.r0[23:16], merge_to_t3)
#define LUT32(ROUND)    TABLE_LUT(aes_sbox_lut_32_r##ROUND, meta.aes.r1[15: 8], merge_to_t3)
#define LUT33(ROUND)    TABLE_LUT(aes_sbox_lut_33_r##ROUND, meta.aes.r2[7 : 0], merge_to_t3)

// We need one copy of all tables for each round. Otherwise, there's dependency issue...
#define GENERATE_ALL_TABLE_LUT(ROUND)   LUT00(ROUND) LUT01(ROUND) LUT02(ROUND) LUT03(ROUND) \
                                        LUT10(ROUND) LUT11(ROUND) LUT12(ROUND) LUT13(ROUND) \
                                        LUT20(ROUND) LUT21(ROUND) LUT22(ROUND) LUT23(ROUND) \
                                        LUT30(ROUND) LUT31(ROUND) LUT32(ROUND) LUT33(ROUND)
GENERATE_ALL_TABLE_LUT(1)
GENERATE_ALL_TABLE_LUT(2)
GENERATE_ALL_TABLE_LUT(3)
GENERATE_ALL_TABLE_LUT(4)
GENERATE_ALL_TABLE_LUT(5)
GENERATE_ALL_TABLE_LUT(6)
GENERATE_ALL_TABLE_LUT(7)
GENERATE_ALL_TABLE_LUT(8)
GENERATE_ALL_TABLE_LUT(9)
GENERATE_ALL_TABLE_LUT(10)
GENERATE_ALL_TABLE_LUT(11)
GENERATE_ALL_TABLE_LUT(12)
GENERATE_ALL_TABLE_LUT(13)


//Only round 1-9 requires mixcolumns. round 10 is different:
// LAST round is special, use SBOX directly as LUT
TABLE_LUT(aes_sbox_lut_00_rLAST, meta.aes.r0[31:24], merge_to_t0_slice0)
TABLE_LUT(aes_sbox_lut_01_rLAST, meta.aes.r1[23:16], merge_to_t0_slice1)
TABLE_LUT(aes_sbox_lut_02_rLAST, meta.aes.r2[15: 8], merge_to_t0_slice2)
TABLE_LUT(aes_sbox_lut_03_rLAST, meta.aes.r3[7 : 0], merge_to_t0_slice3)

TABLE_LUT(aes_sbox_lut_10_rLAST, meta.aes.r1[31:24], merge_to_t1_slice0)
TABLE_LUT(aes_sbox_lut_11_rLAST, meta.aes.r2[23:16], merge_to_t1_slice1)
TABLE_LUT(aes_sbox_lut_12_rLAST, meta.aes.r3[15: 8], merge_to_t1_slice2)
TABLE_LUT(aes_sbox_lut_13_rLAST, meta.aes.r0[7 : 0], merge_to_t1_slice3)

TABLE_LUT(aes_sbox_lut_20_rLAST, meta.aes.r2[31:24], merge_to_t2_slice0)
TABLE_LUT(aes_sbox_lut_21_rLAST, meta.aes.r3[23:16], merge_to_t2_slice1)
TABLE_LUT(aes_sbox_lut_22_rLAST, meta.aes.r0[15: 8], merge_to_t2_slice2)
TABLE_LUT(aes_sbox_lut_23_rLAST, meta.aes.r1[7 : 0], merge_to_t2_slice3)

TABLE_LUT(aes_sbox_lut_30_rLAST, meta.aes.r3[31:24], merge_to_t3_slice0)
TABLE_LUT(aes_sbox_lut_31_rLAST, meta.aes.r0[23:16], merge_to_t3_slice1)
TABLE_LUT(aes_sbox_lut_32_rLAST, meta.aes.r1[15: 8], merge_to_t3_slice2)
TABLE_LUT(aes_sbox_lut_33_rLAST, meta.aes.r2[7 : 0], merge_to_t3_slice3)

#define AP(ROUND,i)  aes_sbox_lut_##i##_r##ROUND##.apply();
#define APPLY_ALL_TABLE_LUT(ROUND)  AP(ROUND,00) AP(ROUND,01) AP(ROUND,02) AP(ROUND,03)  \
                                    AP(ROUND,10) AP(ROUND,11) AP(ROUND,12) AP(ROUND,13)  \
                                    AP(ROUND,20) AP(ROUND,21) AP(ROUND,22) AP(ROUND,23)  \
                                    AP(ROUND,30) AP(ROUND,31) AP(ROUND,32) AP(ROUND,33)

#define AP_SBOX(ROUND,i)  aes_sbox_##i##_r##ROUND##.apply();
#define APPLY_SBOX(ROUND) AP_SBOX(ROUND,00) AP_SBOX(ROUND,01) AP_SBOX(ROUND,02) AP_SBOX(ROUND,03)
#define APPLY_SBOX_256(ROUND) AP_SBOX(ROUND,50) AP_SBOX(ROUND,51) AP_SBOX(ROUND,52) AP_SBOX(ROUND,53)
// Expanded Key
#define APPLY_SBOX_INV_00(ROUND) AP_SBOX(ROUND,10) AP_SBOX(ROUND,11) AP_SBOX(ROUND,12) AP_SBOX(ROUND,13)
#define APPLY_SBOX_INV_01(ROUND) AP_SBOX(ROUND,20) AP_SBOX(ROUND,21) AP_SBOX(ROUND,22) AP_SBOX(ROUND,23)
#define APPLY_SBOX_INV_02(ROUND) AP_SBOX(ROUND,30) AP_SBOX(ROUND,31) AP_SBOX(ROUND,32) AP_SBOX(ROUND,33)
#define APPLY_SBOX_INV_03(ROUND) AP_SBOX(ROUND,40) AP_SBOX(ROUND,41) AP_SBOX(ROUND,42) AP_SBOX(ROUND,43)

// Inv Expanded Key
#define AP_LUT_EXP(ROUND,i)  aes_sbox_lut_exp_##i##_r##ROUND##.apply();
#define APPLY_LUT_EXP_00(ROUND)  AP_LUT_EXP(ROUND,00) AP_LUT_EXP(ROUND,01) AP_LUT_EXP(ROUND,02) AP_LUT_EXP(ROUND,03)
#define APPLY_LUT_EXP_01(ROUND)  AP_LUT_EXP(ROUND,10) AP_LUT_EXP(ROUND,11) AP_LUT_EXP(ROUND,12) AP_LUT_EXP(ROUND,13)
#define APPLY_LUT_EXP_02(ROUND)  AP_LUT_EXP(ROUND,20) AP_LUT_EXP(ROUND,21) AP_LUT_EXP(ROUND,22) AP_LUT_EXP(ROUND,23)
#define APPLY_LUT_EXP_03(ROUND)  AP_LUT_EXP(ROUND,30) AP_LUT_EXP(ROUND,31) AP_LUT_EXP(ROUND,32) AP_LUT_EXP(ROUND,33)

    apply {
        // Init variables
        encryptKey256 = 0x00000000000000000000000000000000000000000000000000000000000000 ; // default
        decryptKey256 = 0x00000000000000000000000000000000000000000000000000000000000000 ; // default
        flag = 0x1; // default
        t = 0x00000000;
        keysize = 0x2; // default
        t_par0 = 0x00000000;
        t_par1 = 0x00000000;
        t_par2 = 0x00000000;
        t_par3 = 0x00000000;
        word0 = 0x00;
        word1 = 0x00;
        word2 = 0x00;
        word3 = 0x00;
        t0_inv = 0x00000000;
        t1_inv = 0x00000000;
        t2_inv = 0x00000000;
        t3_inv = 0x00000000;
        ti0 = 0x00000000;
        ti1 = 0x00000000;
        ti2 = 0x00000000;
        ti3 = 0x00000000;

        if (forward.apply().hit) {

            if (hdr.pkt_ack.isValid() && hdr.pkt_ack.value == 0x11){
                bit<112> header_;
                bit<128> payload_;
                header_ = hdr.ethernet.dstAddr ++ hdr.ethernet.srcAddr ++ hdr.ethernet.etherType;
                payload_ = hdr.aes_inout.value;
                register_data.write(0, (header_ ++ payload_));
            }

            if ((hdr.pkt_ack.isValid() && hdr.pkt_ack.value != 0x22) || hdr.ethernet.etherType == 0x812) {
                if (hdr.pkt_ack.isValid() && hdr.pkt_ack.value == 0x11){
                    hdr.ethernet.etherType = 0x812;
                    proceed_dh();
                    hdr.dh_probe[0].flag = 0x00;
                    standard_metadata.egress_spec = 3;
                }
                else{
                    if (hdr.dh_probe[0].isValid() && hdr.dh_probe[0].flag == 0x00){
                        register_pub_keys.write(0, hdr.dh_probe[0].public_key);
                        hdr.ethernet.etherType = 0x813;
                        //hdr.ethernet.srcAddr = 0x000000000001; // this is not desirable
                        proceed_dh();
                        standard_metadata.egress_spec = 3;
                    }
                    else if (hdr.dh_probe[0].isValid() && hdr.dh_probe[0].flag == 0x01){
                        compute_secret_dh_ph1();
                        proceed_data();

                        data_t dataT_;
                        bit<112> header_;
                        bit<128> payload_;
                        register_data.read(dataT_, 0);
                        payload_ = dataT_[127:0];

                        hdr.aes_inout.value = payload_;
                        hdr.ethernet.etherType = 0x9999;
                     }
                 }
             }

             if (hdr.ethernet.etherType == 0x813 && hdr.dh_probe[0].flag == 0x04){
                bit<256> Ka = (G^P) & hdr.dh_probe[0].public_key;  // this is actually priv key
                meta.dh[0].pu = Ka;

                register_pub_keys.write(0, Ka);
                register_priv_keys.write(0, hdr.dh_probe[0].public_key);

                proceed_dh();
                hdr.ethernet.etherType = 0x812;
                //standard_metadata.egress_spec = 2;
                hdr.dh_probe[0].flag = 0x00;
                data_t dataT_;
                bit<112> header_;
                register_data.read(dataT_, 0);
                header_ = dataT_[239:128];
                hdr.ethernet.srcAddr = header_[63:16];
                write_pubKey();
            }

            else if (hdr.ethernet.etherType == 0x814 && hdr.dh_probe[0].flag == 0x04){
                bit<256> Ka = (G^P) & hdr.dh_probe[0].public_key;  // this is actually priv key
                meta.dh[0].pu = Ka;

                register_priv_keys.write(0, hdr.dh_probe[0].public_key);

                proceed_dh();
                hdr.ethernet.etherType = 0x812;
                hdr.dh_probe[0].flag = 0x01;

                macAddr_t srcAddr;
                srcAddr = hdr.ethernet.srcAddr;
                hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
                //set the destination mac address that we got from the match in the table
                hdr.ethernet.dstAddr = srcAddr;
                //set the output port that we also get from the table
                //standard_metadata.egress_spec = 2;

                write_pubKey();
            }

            if (hdr.ethernet.etherType == 0x9999) {

                if (hdr.pkt_ack.isValid() && hdr.pkt_ack.value == 0x22){
                    compute_secret_dh_ph2();
                }

                bit<256> get_key;
                register_secret_keys.read(get_key, 0);

                // Store the 256 key, but can be used the 128 or 192 bits if needed
                secretKey256 = get_key;

                // To be use for the encrypt and decrypt process
                secretKey128 = get_key[255:128];

                // Set Key for wexpand process
                // This will set the key R0 and R1 depending the size
                set_aes_key(secretKey256);

                // Expand Key
                // keysize 0x0 -> Key 128bits
                // keysize 0x1 -> Key 192bits
                // keysize 0x2 -> Key 256bits
                // Key encrypt R1
                if (keysize == 0x0){expand_set_t_01_r0();}
                if (keysize == 0x1){expand_set_t_02_r0();}
                if (keysize == 0x0 || keysize == 0x1){APPLY_SBOX(0);merge_rcon_to_w0_r0();}
                if (keysize == 0x0){expand_01_r0();expand_02_r0();expand_set_t_02_r0();expand_03_r0();}
                if (keysize == 0x1){expand_03_192_r0();}

                // Key encrypt R2
                expand_set_t_01_r1();
                if (keysize == 0x0 || keysize == 0x2){APPLY_SBOX(1);}
                if (keysize == 0x0){merge_rcon_to_w0_r1();expand_01_r1();expand_02_r1();expand_set_t_02_r1();expand_03_r1();}
                if (keysize == 0x1){expand_01_192_r1();expand_02_192_r1();expand_set_t_02_r1();expand_03_192_r1();}
                if (keysize == 0x2){merge_rcon_to_w0_r0();expand_01_256_r1();expand_02_256_r1();expand_set_t_02_r1();expand_03_256_r1();}

                // Key encrypt R3
                expand_set_t_01_r2();
                if (keysize == 0x0 || keysize == 0x1){APPLY_SBOX(2);}
                if (keysize == 0x0){merge_rcon_to_w0_r2();expand_01_r2();expand_02_r2();expand_set_t_02_r2();expand_03_r2();}
                if (keysize == 0x1){merge_rcon_to_w0_r1();expand_01_192_r2();expand_02_192_r2();expand_set_t_02_r2();expand_03_192_r2();}
                if (keysize == 0x2){APPLY_SBOX_256(0);expand_01_256_r2();expand_02_256_r2();expand_set_t_02_r2();expand_03_256_r2();}

                // Key encrypt R4
                expand_set_t_01_r3();
                if (keysize == 0x1){expand_01_192_r3();expand_02_192_r3();expand_set_t_02_r3();}
                APPLY_SBOX(3);
                if (keysize == 0x0){merge_rcon_to_w0_r3();expand_01_r3();expand_02_r3();expand_set_t_02_r3();expand_03_r3();}
                if (keysize == 0x2){merge_rcon_to_w0_r1();expand_01_256_r3();expand_02_256_r3();expand_set_t_02_r3();expand_03_256_r3();}
                if (keysize == 0x1){merge_rcon_to_w0_r2();expand_03_192_r3();}

                // Key encrypt R5
                expand_set_t_01_r4();
                if (keysize == 0x0){APPLY_SBOX(4);merge_rcon_to_w0_r4();expand_01_r4();expand_02_r4();expand_set_t_02_r4();expand_03_r4();}
                if (keysize == 0x1){expand_01_192_r4();expand_02_192_r4();expand_set_t_02_r4();expand_03_192_r4();}
                if (keysize == 0x2){APPLY_SBOX_256(1);expand_01_256_r4();expand_02_256_r4();expand_set_t_02_r4();expand_03_256_r4();}

                // Key encrypt R6
                expand_set_t_01_r5();APPLY_SBOX(5);
                if (keysize == 0x0){merge_rcon_to_w0_r5();expand_01_r5();expand_02_r5();expand_set_t_02_r5();expand_03_r5();}
                if (keysize == 0x1){merge_rcon_to_w0_r3();expand_01_192_r5();expand_02_192_r5();expand_set_t_02_r5();expand_03_192_r5();}
                if (keysize == 0x2){merge_rcon_to_w0_r2();expand_01_256_r5();expand_02_256_r5();expand_set_t_02_r5();expand_03_256_r5();}

                // Key encrypt R7
                expand_set_t_01_r6();
                if (keysize == 0x1){expand_01_192_r6();expand_02_192_r6();expand_set_t_02_r6();}
                if (keysize == 0x0 || keysize == 0x1){APPLY_SBOX(6);}
                if (keysize == 0x0){merge_rcon_to_w0_r6();expand_01_r6();expand_02_r6();expand_set_t_02_r6();expand_03_r6();}
                if (keysize == 0x1){merge_rcon_to_w0_r4();expand_03_192_r6();}
                if (keysize == 0x2){APPLY_SBOX_256(2);expand_01_256_r6();expand_02_256_r6();expand_set_t_02_r6();expand_03_256_r6();}

                // Key encrypt R8
                expand_set_t_01_r7();
                if (keysize == 0x0 || keysize == 0x2){APPLY_SBOX(7);}
                if (keysize == 0x0){merge_rcon_to_w0_r7();expand_01_r7();expand_02_r7();expand_set_t_02_r7();expand_03_r7();}
                if (keysize == 0x1){expand_01_192_r7();expand_02_192_r7();expand_set_t_02_r7();expand_03_192_r7();}
                if (keysize == 0x2){merge_rcon_to_w0_r3();expand_01_256_r7();expand_02_256_r7();expand_set_t_02_r7();expand_03_256_r7();}

                // Key encrypt R9
                expand_set_t_01_r8();
                if (keysize == 0x0 || keysize == 0x1){APPLY_SBOX(8);}
                if (keysize == 0x0){merge_rcon_to_w0_r8();expand_01_r8();expand_02_r8();expand_set_t_02_r8();expand_03_r8();}
                if (keysize == 0x1){merge_rcon_to_w0_r5();expand_01_192_r8();expand_02_192_r8();expand_set_t_02_r8();expand_03_192_r8();}
                if (keysize == 0x2){APPLY_SBOX_256(3);expand_01_256_r8();expand_02_256_r8();expand_set_t_02_r8();expand_03_256_r8();}

                // Key encrypt R10
                expand_set_t_01_r9();
                if (keysize == 0x1){expand_01_192_r9();expand_02_192_r9();expand_set_t_02_r9();}
                APPLY_SBOX(9);
                if (keysize == 0x0){merge_rcon_to_w0_r9();expand_01_r9();expand_02_r9();expand_set_t_02_r9();expand_03_r9();}
                if (keysize == 0x1){merge_rcon_to_w0_r6();expand_03_192_r9();}
                if (keysize == 0x2){merge_rcon_to_w0_r4();expand_01_256_r9();expand_02_256_r9();expand_set_t_02_r9();expand_03_256_r9();}

                if (keysize == 0x1 || keysize == 0x2){
                    // Key encrypt R11
                    expand_set_t_01_r10();
                    if (keysize == 0x1){expand_01_192_r10();expand_02_192_r10();expand_set_t_02_r10();expand_03_192_r10();}
                    if (keysize == 0x2){APPLY_SBOX_256(4);expand_01_256_r10();expand_02_256_r10();expand_set_t_02_r10();expand_03_256_r10();}

                    // Key encrypt R12
                    expand_set_t_01_r11();APPLY_SBOX(10);
                    if (keysize == 0x1){merge_rcon_to_w0_r7();expand_01_192_r11();expand_02_192_r11();expand_set_t_02_r11();expand_03_192_r11();}
                    if (keysize == 0x2){merge_rcon_to_w0_r5();expand_01_256_r11();expand_02_256_r11();expand_set_t_02_r11();expand_03_256_r11();}
                }
                if (keysize == 0x2){
                    // Key encrypt R13
                    expand_set_t_01_r12();
                    APPLY_SBOX_256(5);expand_01_256_r12();expand_02_256_r12();expand_set_t_02_r12();expand_03_256_r12();

                    // Key encrypt R14
                    expand_set_t_01_r13();APPLY_SBOX(11);
                    merge_rcon_to_w0_r6();expand_01_256_r13();expand_02_256_r13();expand_set_t_02_r13();expand_03_256_r13();
                }

                // Expand Inv Key
                // Key decrypt R1
                get_exp_key_r1();
                get_exp_word_00_r0();APPLY_SBOX_INV_00(0);APPLY_LUT_EXP_00(0);expand_inv_00_r0();
                get_exp_word_01_r0();APPLY_SBOX_INV_01(0);APPLY_LUT_EXP_01(0);expand_inv_01_r0();
                get_exp_word_02_r0();APPLY_SBOX_INV_02(0);APPLY_LUT_EXP_02(0);expand_inv_02_r0();
                get_exp_word_03_r0();APPLY_SBOX_INV_03(0);APPLY_LUT_EXP_03(0);expand_inv_03_r0();
                // Key decrypt R2
                get_exp_key_r2();
                get_exp_word_00_r1();APPLY_SBOX_INV_00(1);APPLY_LUT_EXP_00(1);expand_inv_00_r1();
                get_exp_word_01_r1();APPLY_SBOX_INV_01(1);APPLY_LUT_EXP_01(1);expand_inv_01_r1();
                get_exp_word_02_r1();APPLY_SBOX_INV_02(1);APPLY_LUT_EXP_02(1);expand_inv_02_r1();
                get_exp_word_03_r1();APPLY_SBOX_INV_03(1);APPLY_LUT_EXP_03(1);expand_inv_03_r1();
                // Key decrypt R3
                get_exp_key_r3();
                get_exp_word_00_r2();APPLY_SBOX_INV_00(2);APPLY_LUT_EXP_00(2);expand_inv_00_r2();
                get_exp_word_01_r2();APPLY_SBOX_INV_01(2);APPLY_LUT_EXP_01(2);expand_inv_01_r2();
                get_exp_word_02_r2();APPLY_SBOX_INV_02(2);APPLY_LUT_EXP_02(2);expand_inv_02_r2();
                get_exp_word_03_r2();APPLY_SBOX_INV_03(2);APPLY_LUT_EXP_03(2);expand_inv_03_r2();
                // Key decrypt R4
                get_exp_key_r4();
                get_exp_word_00_r3();APPLY_SBOX_INV_00(3);APPLY_LUT_EXP_00(3);expand_inv_00_r3();
                get_exp_word_01_r3();APPLY_SBOX_INV_01(3);APPLY_LUT_EXP_01(3);expand_inv_01_r3();
                get_exp_word_02_r3();APPLY_SBOX_INV_02(3);APPLY_LUT_EXP_02(3);expand_inv_02_r3();
                get_exp_word_03_r3();APPLY_SBOX_INV_03(3);APPLY_LUT_EXP_03(3);expand_inv_03_r3();
                // Key decrypt R5
                get_exp_key_r5();
                get_exp_word_00_r4();APPLY_SBOX_INV_00(4);APPLY_LUT_EXP_00(4);expand_inv_00_r4();
                get_exp_word_01_r4();APPLY_SBOX_INV_01(4);APPLY_LUT_EXP_01(4);expand_inv_01_r4();
                get_exp_word_02_r4();APPLY_SBOX_INV_02(4);APPLY_LUT_EXP_02(4);expand_inv_02_r4();
                get_exp_word_03_r4();APPLY_SBOX_INV_03(4);APPLY_LUT_EXP_03(4);expand_inv_03_r4();
                // Key decrypt R6
                get_exp_key_r6();
                get_exp_word_00_r5();APPLY_SBOX_INV_00(5);APPLY_LUT_EXP_00(5);expand_inv_00_r5();
                get_exp_word_01_r5();APPLY_SBOX_INV_01(5);APPLY_LUT_EXP_01(5);expand_inv_01_r5();
                get_exp_word_02_r5();APPLY_SBOX_INV_02(5);APPLY_LUT_EXP_02(5);expand_inv_02_r5();
                get_exp_word_03_r5();APPLY_SBOX_INV_03(5);APPLY_LUT_EXP_03(5);expand_inv_03_r5();
                // Key decrypt R7
                get_exp_key_r7();
                get_exp_word_00_r6();APPLY_SBOX_INV_00(6);APPLY_LUT_EXP_00(6);expand_inv_00_r6();
                get_exp_word_01_r6();APPLY_SBOX_INV_01(6);APPLY_LUT_EXP_01(6);expand_inv_01_r6();
                get_exp_word_02_r6();APPLY_SBOX_INV_02(6);APPLY_LUT_EXP_02(6);expand_inv_02_r6();
                get_exp_word_03_r6();APPLY_SBOX_INV_03(6);APPLY_LUT_EXP_03(6);expand_inv_03_r6();
                // Key decrypt R8
                get_exp_key_r8();
                get_exp_word_00_r7();APPLY_SBOX_INV_00(7);APPLY_LUT_EXP_00(7);expand_inv_00_r7();
                get_exp_word_01_r7();APPLY_SBOX_INV_01(7);APPLY_LUT_EXP_01(7);expand_inv_01_r7();
                get_exp_word_02_r7();APPLY_SBOX_INV_02(7);APPLY_LUT_EXP_02(7);expand_inv_02_r7();
                get_exp_word_03_r7();APPLY_SBOX_INV_03(7);APPLY_LUT_EXP_03(7);expand_inv_03_r7();
                // Key decrypt R9
                get_exp_key_r9();
                get_exp_word_00_r8();APPLY_SBOX_INV_00(8);APPLY_LUT_EXP_00(8);expand_inv_00_r8();
                get_exp_word_01_r8();APPLY_SBOX_INV_01(8);APPLY_LUT_EXP_01(8);expand_inv_01_r8();
                get_exp_word_02_r8();APPLY_SBOX_INV_02(8);APPLY_LUT_EXP_02(8);expand_inv_02_r8();
                get_exp_word_03_r8();APPLY_SBOX_INV_03(8);APPLY_LUT_EXP_03(8);expand_inv_03_r8();
                // Key decrypt R10
                if (keysize == 0x0){meta.aes.inv_expandkey_r10 = meta.aes.expandkey_r10;}
                if (keysize == 0x1 || keysize == 0x2){
                    get_exp_key_r10();
                    get_exp_word_00_r9();APPLY_SBOX_INV_00(9);APPLY_LUT_EXP_00(9);expand_inv_00_r9();
                    get_exp_word_01_r9();APPLY_SBOX_INV_01(9);APPLY_LUT_EXP_01(9);expand_inv_01_r9();
                    get_exp_word_02_r9();APPLY_SBOX_INV_02(9);APPLY_LUT_EXP_02(9);expand_inv_02_r9();
                    get_exp_word_03_r9();APPLY_SBOX_INV_03(9);APPLY_LUT_EXP_03(9);expand_inv_03_r9();
                    // Key decrypt R11
                    get_exp_key_r11();
                    get_exp_word_00_r10();APPLY_SBOX_INV_00(10);APPLY_LUT_EXP_00(10);expand_inv_00_r10();
                    get_exp_word_01_r10();APPLY_SBOX_INV_01(10);APPLY_LUT_EXP_01(10);expand_inv_01_r10();
                    get_exp_word_02_r10();APPLY_SBOX_INV_02(10);APPLY_LUT_EXP_02(10);expand_inv_02_r10();
                    get_exp_word_03_r10();APPLY_SBOX_INV_03(10);APPLY_LUT_EXP_03(10);expand_inv_03_r10();
                }
                // Key decrypt R12
                if (keysize == 0x1){meta.aes.inv_expandkey_r12 = meta.aes.expandkey_r12;}
                if (keysize == 0x2){
                    get_exp_key_r12();
                    get_exp_word_00_r11();APPLY_SBOX_INV_00(11);APPLY_LUT_EXP_00(11);expand_inv_00_r11();
                    get_exp_word_01_r11();APPLY_SBOX_INV_01(11);APPLY_LUT_EXP_01(11);expand_inv_01_r11();
                    get_exp_word_02_r11();APPLY_SBOX_INV_02(11);APPLY_LUT_EXP_02(11);expand_inv_02_r11();
                    get_exp_word_03_r11();APPLY_SBOX_INV_03(11);APPLY_LUT_EXP_03(11);expand_inv_03_r11();
                    // Key decrypt R13
                    get_exp_key_r13();
                    get_exp_word_00_r12();APPLY_SBOX_INV_00(12);APPLY_LUT_EXP_00(12);expand_inv_00_r12();
                    get_exp_word_01_r12();APPLY_SBOX_INV_01(12);APPLY_LUT_EXP_01(12);expand_inv_01_r12();
                    get_exp_word_02_r12();APPLY_SBOX_INV_02(12);APPLY_LUT_EXP_02(12);expand_inv_02_r12();
                    get_exp_word_03_r12();APPLY_SBOX_INV_03(12);APPLY_LUT_EXP_03(12);expand_inv_03_r12();
                }
                // Key decrypt R14
                if (keysize == 0x2){meta.aes.inv_expandkey_r14 = meta.aes.expandkey_r14;}

                if (hdr.pkt_ack.isValid() && hdr.pkt_ack.value == 0x00){
                    read_payload();
                    mask_key(secretKey128);
                    new_round(); APPLY_ALL_TABLE_LUT(1); mask_key(meta.aes.expandkey_r1);
                    new_round(); APPLY_ALL_TABLE_LUT(2); mask_key(meta.aes.expandkey_r2);
                    new_round(); APPLY_ALL_TABLE_LUT(3); mask_key(meta.aes.expandkey_r3);
                    new_round(); APPLY_ALL_TABLE_LUT(4); mask_key(meta.aes.expandkey_r4);
                    new_round(); APPLY_ALL_TABLE_LUT(5); mask_key(meta.aes.expandkey_r5);
                    new_round(); APPLY_ALL_TABLE_LUT(6); mask_key(meta.aes.expandkey_r6);
                    new_round(); APPLY_ALL_TABLE_LUT(7); mask_key(meta.aes.expandkey_r7);
                    new_round(); APPLY_ALL_TABLE_LUT(8); mask_key(meta.aes.expandkey_r8);
                    new_round(); APPLY_ALL_TABLE_LUT(9); mask_key(meta.aes.expandkey_r9);

                    if (keysize == 0x1 || keysize == 0x2){
                        new_round(); APPLY_ALL_TABLE_LUT(10); mask_key(meta.aes.expandkey_r10);
                        new_round(); APPLY_ALL_TABLE_LUT(11); mask_key(meta.aes.expandkey_r11);
                    }
                    if (keysize == 0x2){
                        new_round(); APPLY_ALL_TABLE_LUT(12); mask_key(meta.aes.expandkey_r12);
                        new_round(); APPLY_ALL_TABLE_LUT(13); mask_key(meta.aes.expandkey_r13);
                    }

                    new_round(); APPLY_ALL_TABLE_LUT(LAST);

                    if (keysize == 0x0){mask_key(meta.aes.expandkey_r10);}
                    if (keysize == 0x1){mask_key(meta.aes.expandkey_r12);}
                    if (keysize == 0x2){mask_key(meta.aes.expandkey_r14);}

                    hdr.pkt_ack.value = 0x22;
                    reflect();
                    write_payload();
                }
                else if (hdr.pkt_ack.isValid() && hdr.pkt_ack.value == 0x22){
                    read_payload();
                    if (keysize == 0x2){
                        mask_key(meta.aes.expandkey_r14);
                        new_round(); APPLY_ALL_UNTABLE_LUT(13); mask_key(meta.aes.inv_expandkey_r13);
                        new_round(); APPLY_ALL_UNTABLE_LUT(12); mask_key(meta.aes.inv_expandkey_r12);
                    }
                    if (keysize == 0x1 || keysize == 0x2){
                        if (keysize == 0x1){
                            mask_key(meta.aes.expandkey_r12);
                        }
                        new_round(); APPLY_ALL_UNTABLE_LUT(11); mask_key(meta.aes.inv_expandkey_r11);
                        new_round(); APPLY_ALL_UNTABLE_LUT(10); mask_key(meta.aes.inv_expandkey_r10);
                    }
                    if (keysize == 0x0){
                        mask_key(meta.aes.expandkey_r10);
                    }
                    new_round(); APPLY_ALL_UNTABLE_LUT(9); mask_key(meta.aes.inv_expandkey_r9);
                    new_round(); APPLY_ALL_UNTABLE_LUT(8); mask_key(meta.aes.inv_expandkey_r8);
                    new_round(); APPLY_ALL_UNTABLE_LUT(7); mask_key(meta.aes.inv_expandkey_r7);
                    new_round(); APPLY_ALL_UNTABLE_LUT(6); mask_key(meta.aes.inv_expandkey_r6);
                    new_round(); APPLY_ALL_UNTABLE_LUT(5); mask_key(meta.aes.inv_expandkey_r5);
                    new_round(); APPLY_ALL_UNTABLE_LUT(4); mask_key(meta.aes.inv_expandkey_r4);
                    new_round(); APPLY_ALL_UNTABLE_LUT(3); mask_key(meta.aes.inv_expandkey_r3);
                    new_round(); APPLY_ALL_UNTABLE_LUT(2); mask_key(meta.aes.inv_expandkey_r2);
                    new_round(); APPLY_ALL_UNTABLE_LUT(1); mask_key(meta.aes.inv_expandkey_r1);
                    // one last round, INV S-box only
                    new_round(); APPLY_ALL_UNTABLE_LUT(LAST); mask_key(secretKey128);
                    // End AES
                    write_payload();
                    proceed_data();
                }
            }
        }
    }
}

control MyEgress(
    inout my_headers_t        hdr,
    inout my_metadata_t       meta,
    inout standard_metadata_t standard_metadata) {

    apply {

    }
}

control MyComputeChecksum(
    inout my_headers_t  hdr,
    inout my_metadata_t meta)
{
    apply {   }
}

control MyDeparser(
    packet_out      packet,
    in my_headers_t hdr)
{

    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.dh_probe);
        packet.emit(hdr.pkt_ack);
        packet.emit(hdr.aes_inout);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
