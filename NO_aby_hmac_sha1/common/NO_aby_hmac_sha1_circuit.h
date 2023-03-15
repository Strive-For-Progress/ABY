/**
 \file 		aescircuit.h
 \author 	michael.zohner@ec-spride.de
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2019 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
            it under the terms of the GNU Lesser General Public License as published
            by the Free Software Foundation, either version 3 of the License, or
            (at your option) any later version.
            ABY is distributed in the hope that it will be useful,
            but WITHOUT ANY WARRANTY; without even the implied warranty of
            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
            GNU Lesser General Public License for more details.
            You should have received a copy of the GNU Lesser General Public License
            along with this program. If not, see <http://www.gnu.org/licenses/>.
 \brief		Implementation of the SHA1 hash function (which should not be used in practice anymore!)
 */

#ifndef __SHA1_CIRCUIT_H_
#define __SHA1_CIRCUIT_H_

#include "../../../abycore/circuit/circuit.h"
#include "../../../abycore/aby/abyparty.h"
#include <ENCRYPTO_utils/crypto/crypto.h>
#include <cassert>

class BooleanCircuit;

#define ABY_SHA1_INPUT_BITS 1024
#define ABY_SHA1_INPUT_BYTES ABY_SHA1_INPUT_BITS/8

#define ABY_SHA1_OUTPUT_BITS 160
#define ABY_SHA1_OUTPUT_BYTES ABY_SHA1_OUTPUT_BITS/8

#define SHA1CircularShift(bits,word) \
                ((((word) << (bits)) & 0xFFFFFFFF) | \
                ((word) >> (32-(bits))))

const uint32_t ABY_SHA1_H0 = 0x67452301;
const uint32_t ABY_SHA1_H1 = 0xEFCDAB89;
const uint32_t ABY_SHA1_H2 = 0x98BADCFE;
const uint32_t ABY_SHA1_H3 = 0x10325476;
const uint32_t ABY_SHA1_H4 = 0xC3D2E1F0;

const uint32_t ABY_SHA1_K0 = 0x5A827999;
const uint32_t ABY_SHA1_K1 = 0x6ED9EBA1;
const uint32_t ABY_SHA1_K2 = 0x8F1BBCDC;
const uint32_t ABY_SHA1_K3 = 0xCA62C1D6;

int32_t test_NO_aby_hmac_sha1_circuit(seclvl seclvl, uint32_t nvals);

void BuildHMACSHA1Circuit(uint8_t* msgSi, uint8_t* msgSo, uint8_t* msgC, uint8_t* int_out, uint32_t nvals);
void process_block(uint8_t* msg, uint8_t* tmp_int_out, uint32_t* h, uint32_t nvals);


void init_variables(uint32_t* h, uint32_t nvals);
void break_message_to_chunks(uint32_t* w, uint8_t* msg);
void expand_ws(uint32_t* w);
void sha1_main_loop(uint32_t* h, uint32_t* w, uint32_t nvals);
// void verify_SHA1_hash(uint8_t* msgS, uint8_t* msgC, uint32_t msgbytes_per_party, uint32_t nvals, uint8_t* hash);



#endif /* __SHA1_CIRCUIT_H_ */
