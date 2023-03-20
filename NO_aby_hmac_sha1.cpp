#include <iostream>
#include <cstring>
#include <stdlib.h>
#include <bits/types.h>
#include <time.h>
typedef __int8_t int8_t;
typedef __int16_t int16_t;
typedef __int32_t int32_t;
typedef __int64_t int64_t;
typedef __uint8_t uint8_t;
typedef __uint16_t uint16_t;
typedef __uint32_t uint32_t;
typedef __uint64_t uint64_t;

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


void BuildHMACSHA1Circuit(uint8_t* msgSi, uint8_t* msgSo, uint8_t* msgC, uint8_t* int_out);
void process_block(uint8_t* msg, uint8_t* tmp_int_out, uint32_t* h);
void init_variables(uint32_t* h);
void break_message_to_chunks(uint32_t* w, uint8_t* msg);
void expand_ws(uint32_t* w);
void sha1_main_loop(uint32_t* h, uint32_t* w);

using namespace std;

struct timespec diff(struct timespec start, struct timespec end) {
  struct timespec temp;
  if ((end.tv_nsec-start.tv_nsec)<0) {
    temp.tv_sec = end.tv_sec-start.tv_sec-1;
    temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
  } else {
    temp.tv_sec = end.tv_sec-start.tv_sec;
    temp.tv_nsec = end.tv_nsec-start.tv_nsec;
  }
  return temp;
}

int main() {

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

	uint32_t sha1bits_per_party = ABY_SHA1_INPUT_BITS/2;
	uint32_t sha1bytes_per_party = sha1bits_per_party/8;


	//The plaintext output computation will only be done once instead of nvals times!
	uint8_t* plain_out = (uint8_t*) malloc(ABY_SHA1_OUTPUT_BYTES);
    uint8_t* msgS = (uint8_t*) malloc(ABY_SHA1_INPUT_BYTES);
    uint8_t* msgSi = (uint8_t*) malloc(ABY_SHA1_INPUT_BYTES);
    uint8_t* msgSo = (uint8_t*) malloc(ABY_SHA1_INPUT_BYTES);
    uint8_t* msgC = (uint8_t*) malloc(ABY_SHA1_INPUT_BYTES);


    // Input (key -> key_xoripad, key_xor_opad)
	uint32_t key = 0x12;
	for(uint32_t i = 0; i < sha1bytes_per_party; i++) {
        if(i == 0) {
            msgS[i] = key;
            msgSi[i] = key ^ 0x36;
            msgSo[i] = key ^ 0x5c;         
        } else {
            msgS[i] = 0x00;
            msgSi[i] = 0x36;
            msgSo[i] = 0x5c;
        }
	}
    // Input (msg)
    for(uint32_t i = 0; i < sha1bytes_per_party; i++) {
        if(i == 0) {
            msgC[i] = 0xef;
        } else {
            msgC[i] = 0x00;
        }
	}

	BuildHMACSHA1Circuit(msgSi, msgSo, msgC, plain_out);


    // output
	cout << "Testing HMACSHA1 " << endl;

	cout << "Key     : ";
	for(int i = 0; i < 64 ; i++) printf("%02x",msgS[i]);
	cout << "\n\n";	

    cout << "Msg     : ";
	for(int i = 0; i < 64 ; i++) printf("%02x",msgC[i]);
	cout << "\n\n";

	cout << "Hmacsha1: ";
	for(int i = 0; i < 20 ; i++) printf("%02x",plain_out[i]);
	cout << "\n\n";

    clock_gettime(CLOCK_MONOTONIC, &end);
    struct timespec temp = diff(start, end);
    printf( "Time    : %lds%09ld\n", temp.tv_sec, temp.tv_nsec);
	return 0;
}

/* Steps are taken from the wikipedia article on SHA1 */
void BuildHMACSHA1Circuit(uint8_t* msgSi, uint8_t* msgSo, uint8_t* msgC, uint8_t* plain_out) {

	uint32_t party_in_bitlen = ABY_SHA1_INPUT_BITS/2;
	uint32_t party_in_bytelen = ABY_SHA1_INPUT_BYTES/2;


	//Copy plaintext input into one msg
	uint8_t* tmp_plain_out = (uint8_t*) malloc(ABY_SHA1_OUTPUT_BYTES);
	uint8_t* first_sha1_plain_out = (uint8_t*) malloc(ABY_SHA1_OUTPUT_BYTES);
	uint8_t* msg = (uint8_t*) malloc(ABY_SHA1_INPUT_BYTES);
	memcpy(msg, msgSi, party_in_bytelen);


	//initialize state variables
	uint32_t* h = (uint32_t*) malloc(sizeof(uint32_t) * 5);
	init_variables(h);

	/*
	 * Process this message block
	 */
	process_block(msg, tmp_plain_out, h);


	/*
	 * Process this(second) message block
	 */
	memcpy(msg, msgC, party_in_bytelen);
	process_block(msg, tmp_plain_out, h);

	/*
	 * Do the final SHA1 Result computation.
	 * TODO: The remaining block should be padded and processed here. However, since the
	 * input bit length is fixed to 512 bit, the padding is constant.
	 */

	for(uint32_t i = 0; i < 64; i++) {
		if(i == 0) {
			msg[0] = 0x80;
		} else if (i == 62) {
			msg[62] = 0x04;
		} else {
			msg[i] = 0;
		}
	}
	process_block(msg, tmp_plain_out, h);
	memcpy(first_sha1_plain_out, tmp_plain_out, ABY_SHA1_OUTPUT_BYTES);

	// 2nd sha1
	init_variables(h);

	memcpy(msg, msgSo, party_in_bytelen);
	process_block(msg, tmp_plain_out, h);


	for(uint32_t i = 0; i < 64; i++) {
		if(i < 20) {
			msg[i] = first_sha1_plain_out[i];
		} else if(i == 20) {
			msg[i] = 0x80;
		} else if(i == 62) {
			msg[i] = 0x02;
		} else if(i == 63) {
			msg[i] = 0xA0;
		} else {
			msg[i] = 0x00;
		}
	}
	process_block(msg, tmp_plain_out, h);

	memcpy(plain_out, tmp_plain_out, ABY_SHA1_OUTPUT_BYTES);

	free(h);
	return ;
}



void init_variables(uint32_t* h) {
	
	/* Initialize variables
	* h0 = 0x67452301
	* h1 = 0xEFCDAB89
	* h2 = 0x98BADCFE
	* h3 = 0x10325476
	* h4 = 0xC3D2E1F0
	*/	
	h[0] = ABY_SHA1_H0;
	h[1] = ABY_SHA1_H1;
	h[2] = ABY_SHA1_H2;
	h[3] = ABY_SHA1_H3;
	h[4] = ABY_SHA1_H4;

}

void process_block(uint8_t* msg, uint8_t* plain_out, uint32_t* h) {


	uint32_t* w = (uint32_t*) malloc(sizeof(uint32_t) * 80);

	//break message into 512-bit chunks
	//for each chunk
	//    break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
	break_message_to_chunks(w, msg);

    //for i from 16 to 79
     //   w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
	expand_ws(w);

	//Main Loop; result is written into s_h
	sha1_main_loop(h, w);

	for(uint32_t i = 0; i < 5; i++) {
		plain_out[i*4] = (h[i]>>24)&0xFF;
		plain_out[i*4+1] = (h[i]>>16)&0xFF;
		plain_out[i*4+2] = (h[i]>>8)&0xFF;
		plain_out[i*4+3] = (h[i])&0xFF;
	}

	free(w);

	return ;
}

void break_message_to_chunks(uint32_t* w, uint8_t* msg) {
	//iterate over message bytes
	uint32_t wid;
	for(uint32_t i = 0; i < 16; i++) {
		//iterate over bits
		w[i] = msg[i*4] << 24;
		w[i] |= (msg[i*4+1] << 16);
		w[i] |= (msg[i*4+2] << 8);
		w[i] |= msg[i*4+3];
	}
}

void expand_ws(uint32_t* w) {
	for(uint32_t i = 16; i < 80; i++) {
		w[i] = SHA1CircularShift(1, w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]);
	}
}

void sha1_main_loop(uint32_t* h, uint32_t* w) {
	/*
	 * Initialize hash value for this chunk:
	 * a = h0; b = h1; c = h2; d = h3; e = h4
	*/
	uint32_t a, b, c, d, e;
	a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];

	/*
	 * Main loop
	 * for i from 0 to 79
	 */
	uint32_t f, k, tmp;
	for(uint32_t i = 0; i < 80; i++) {

		if(i < 20) {
		/*
		 * if 0 ≤ i ≤ 19 then
		 *     f = (b and c) xor ((not b) and d)
		 *     k = 0x5A827999
		 */
			f = (b & c) | ((~b) & d);
			k = ABY_SHA1_K0;
		} else if(i < 40) {
		/*
         * else if 20 ≤ i ≤ 39
         * 		f = b xor c xor d
         * 		k = 0x6ED9EBA1
		 */
			f = b ^ c ^ d;
			k = ABY_SHA1_K1;
		} else if(i < 60) {
		/*
         * else if 40 ≤ i ≤ 59
         * 		f = (b and c) xor (b and d) xor (c and d)
         *  	k = 0x8F1BBCDC
		 */
			f = (b & c) | (b & d) | (c & d);
			k = ABY_SHA1_K2;
		} else if(i < 80) {
			/*
      	  	 * else if 60 ≤ i ≤ 79
             * 		f = b xor c xor d
             * 		k = 0xCA62C1D6
			 */
			f = (b ^ c ^ d);
			k = ABY_SHA1_K3;
		}
		/*
		 * temp = (a leftrotate 5) + f + e + k + w[i]
		 */
		tmp = SHA1CircularShift(5, a);
		tmp = (tmp + f) & 0xFFFFFFFF;
		tmp = (tmp + e) & 0xFFFFFFFF;
		tmp = (tmp + k) & 0xFFFFFFFF;
		tmp = (tmp + w[i]) & 0xFFFFFFFF;

		// e = d
		e = d;
        // d = c
		d = c;
		// c = b leftrotate 30
		c = SHA1CircularShift(30, b);
		// b = a
		b = a;
		// a = temp
		a = tmp;

	}

	/*
	 * Set output; Add this chunk's hash to result so far:
	 * h0 = h0 + a; h1 = h1 + b; h2 = h2 + c; h3 = h3 + d; h4 = h4 + e
	 */

	h[0] = (h[0] + a) & 0xFFFFFFFF;
	h[1] = (h[1] + b) & 0xFFFFFFFF;
	h[2] = (h[2] + c) & 0xFFFFFFFF;
	h[3] = (h[3] + d) & 0xFFFFFFFF;
	h[4] = (h[4] + e) & 0xFFFFFFFF;
}