/*
 * Cryptographic API.
 *
 * SHA-256, as specified in
 * http://csrc.nist.gov/groups/STM/cavp/documents/shs/sha256-384-512.pdf
 *
 * SHA-256 code by Jean-Luc Cooke <jlcooke@certainkey.com>.
 *
 * Copyright (c) Jean-Luc Cooke <jlcooke@certainkey.com>
 * Copyright (c) Andrew McDonald <andrew@mcdonald.org.uk>
 * Copyright (c) 2002 James Morris <jmorris@intercode.com.au>
 * SHA224 Support Copyright 2007 Intel Corporation <jonathan.lynch@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

#include "config.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "miner.h"

typedef uint32_t u32;
typedef uint8_t u8;

static inline u32 ror32(u32 word, unsigned int shift) {
	return (word >> shift) | (word << (32 - shift));
}

static inline u32 Ch(u32 x, u32 y, u32 z) {
	return z ^ (x & (y ^ z));
}

static inline u32 Maj(u32 x, u32 y, u32 z) {
	return (x & y) | (z & (x | y));
}

#define e0(x)       (ror32(x, 2) ^ ror32(x,13) ^ ror32(x,22))
#define e1(x)       (ror32(x, 6) ^ ror32(x,11) ^ ror32(x,25))
#define s0(x)       (ror32(x, 7) ^ ror32(x,18) ^ (x >> 3))
#define s1(x)       (ror32(x,17) ^ ror32(x,19) ^ (x >> 10))

static inline void LOAD_OP(int I, u32 *W, const u8 *input) {
	/* byteswap is commented out, because bitcoin input
	 * is already big-endian
	 */
	W[I] = /* ntohl */(((u32*) (input))[I]);
}

static inline void BLEND_OP(int I, u32 *W) {
	W[I] = s1(W[I-2]) + W[I - 7] + s0(W[I-15]) + W[I - 16];
}

static void sha256_transform(u32 *state, const u8 *input) {
	u32 a, b, c, d, e, f, g, h, t1, t2;
	u32 W[64];
	int i;

	/* load the input */
	for (i = 0; i < 16; i++)
		LOAD_OP(i, W, input);

	/* now blend */
	for (i = 16; i < 64; i++)
		BLEND_OP(i, W);

	/* load the state into our registers */
	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];
	e = state[4];
	f = state[5];
	g = state[6];
	h = state[7];

	/* now iterate */
	t1 = h + e1(e) + Ch(e, f, g) + 0x428a2f98 + W[0];
	t2 = e0(a) + Maj(a, b, c);
	d += t1;
	h = t1 + t2;
	t1 = g + e1(d) + Ch(d, e, f) + 0x71374491 + W[1];
	t2 = e0(h) + Maj(h, a, b);
	c += t1;
	g = t1 + t2;
	t1 = f + e1(c) + Ch(c, d, e) + 0xb5c0fbcf + W[2];
	t2 = e0(g) + Maj(g, h, a);
	b += t1;
	f = t1 + t2;
	t1 = e + e1(b) + Ch(b, c, d) + 0xe9b5dba5 + W[3];
	t2 = e0(f) + Maj(f, g, h);
	a += t1;
	e = t1 + t2;
	t1 = d + e1(a) + Ch(a, b, c) + 0x3956c25b + W[4];
	t2 = e0(e) + Maj(e, f, g);
	h += t1;
	d = t1 + t2;
	t1 = c + e1(h) + Ch(h, a, b) + 0x59f111f1 + W[5];
	t2 = e0(d) + Maj(d, e, f);
	g += t1;
	c = t1 + t2;
	t1 = b + e1(g) + Ch(g, h, a) + 0x923f82a4 + W[6];
	t2 = e0(c) + Maj(c, d, e);
	f += t1;
	b = t1 + t2;
	t1 = a + e1(f) + Ch(f, g, h) + 0xab1c5ed5 + W[7];
	t2 = e0(b) + Maj(b, c, d);
	e += t1;
	a = t1 + t2;

	t1 = h + e1(e) + Ch(e, f, g) + 0xd807aa98 + W[8];
	t2 = e0(a) + Maj(a, b, c);
	d += t1;
	h = t1 + t2;
	t1 = g + e1(d) + Ch(d, e, f) + 0x12835b01 + W[9];
	t2 = e0(h) + Maj(h, a, b);
	c += t1;
	g = t1 + t2;
	t1 = f + e1(c) + Ch(c, d, e) + 0x243185be + W[10];
	t2 = e0(g) + Maj(g, h, a);
	b += t1;
	f = t1 + t2;
	t1 = e + e1(b) + Ch(b, c, d) + 0x550c7dc3 + W[11];
	t2 = e0(f) + Maj(f, g, h);
	a += t1;
	e = t1 + t2;
	t1 = d + e1(a) + Ch(a, b, c) + 0x72be5d74 + W[12];
	t2 = e0(e) + Maj(e, f, g);
	h += t1;
	d = t1 + t2;
	t1 = c + e1(h) + Ch(h, a, b) + 0x80deb1fe + W[13];
	t2 = e0(d) + Maj(d, e, f);
	g += t1;
	c = t1 + t2;
	t1 = b + e1(g) + Ch(g, h, a) + 0x9bdc06a7 + W[14];
	t2 = e0(c) + Maj(c, d, e);
	f += t1;
	b = t1 + t2;
	t1 = a + e1(f) + Ch(f, g, h) + 0xc19bf174 + W[15];
	t2 = e0(b) + Maj(b, c, d);
	e += t1;
	a = t1 + t2;

	t1 = h + e1(e) + Ch(e, f, g) + 0xe49b69c1 + W[16];
	t2 = e0(a) + Maj(a, b, c);
	d += t1;
	h = t1 + t2;
	t1 = g + e1(d) + Ch(d, e, f) + 0xefbe4786 + W[17];
	t2 = e0(h) + Maj(h, a, b);
	c += t1;
	g = t1 + t2;
	t1 = f + e1(c) + Ch(c, d, e) + 0x0fc19dc6 + W[18];
	t2 = e0(g) + Maj(g, h, a);
	b += t1;
	f = t1 + t2;
	t1 = e + e1(b) + Ch(b, c, d) + 0x240ca1cc + W[19];
	t2 = e0(f) + Maj(f, g, h);
	a += t1;
	e = t1 + t2;
	t1 = d + e1(a) + Ch(a, b, c) + 0x2de92c6f + W[20];
	t2 = e0(e) + Maj(e, f, g);
	h += t1;
	d = t1 + t2;
	t1 = c + e1(h) + Ch(h, a, b) + 0x4a7484aa + W[21];
	t2 = e0(d) + Maj(d, e, f);
	g += t1;
	c = t1 + t2;
	t1 = b + e1(g) + Ch(g, h, a) + 0x5cb0a9dc + W[22];
	t2 = e0(c) + Maj(c, d, e);
	f += t1;
	b = t1 + t2;
	t1 = a + e1(f) + Ch(f, g, h) + 0x76f988da + W[23];
	t2 = e0(b) + Maj(b, c, d);
	e += t1;
	a = t1 + t2;

	t1 = h + e1(e) + Ch(e, f, g) + 0x983e5152 + W[24];
	t2 = e0(a) + Maj(a, b, c);
	d += t1;
	h = t1 + t2;
	t1 = g + e1(d) + Ch(d, e, f) + 0xa831c66d + W[25];
	t2 = e0(h) + Maj(h, a, b);
	c += t1;
	g = t1 + t2;
	t1 = f + e1(c) + Ch(c, d, e) + 0xb00327c8 + W[26];
	t2 = e0(g) + Maj(g, h, a);
	b += t1;
	f = t1 + t2;
	t1 = e + e1(b) + Ch(b, c, d) + 0xbf597fc7 + W[27];
	t2 = e0(f) + Maj(f, g, h);
	a += t1;
	e = t1 + t2;
	t1 = d + e1(a) + Ch(a, b, c) + 0xc6e00bf3 + W[28];
	t2 = e0(e) + Maj(e, f, g);
	h += t1;
	d = t1 + t2;
	t1 = c + e1(h) + Ch(h, a, b) + 0xd5a79147 + W[29];
	t2 = e0(d) + Maj(d, e, f);
	g += t1;
	c = t1 + t2;
	t1 = b + e1(g) + Ch(g, h, a) + 0x06ca6351 + W[30];
	t2 = e0(c) + Maj(c, d, e);
	f += t1;
	b = t1 + t2;
	t1 = a + e1(f) + Ch(f, g, h) + 0x14292967 + W[31];
	t2 = e0(b) + Maj(b, c, d);
	e += t1;
	a = t1 + t2;

	t1 = h + e1(e) + Ch(e, f, g) + 0x27b70a85 + W[32];
	t2 = e0(a) + Maj(a, b, c);
	d += t1;
	h = t1 + t2;
	t1 = g + e1(d) + Ch(d, e, f) + 0x2e1b2138 + W[33];
	t2 = e0(h) + Maj(h, a, b);
	c += t1;
	g = t1 + t2;
	t1 = f + e1(c) + Ch(c, d, e) + 0x4d2c6dfc + W[34];
	t2 = e0(g) + Maj(g, h, a);
	b += t1;
	f = t1 + t2;
	t1 = e + e1(b) + Ch(b, c, d) + 0x53380d13 + W[35];
	t2 = e0(f) + Maj(f, g, h);
	a += t1;
	e = t1 + t2;
	t1 = d + e1(a) + Ch(a, b, c) + 0x650a7354 + W[36];
	t2 = e0(e) + Maj(e, f, g);
	h += t1;
	d = t1 + t2;
	t1 = c + e1(h) + Ch(h, a, b) + 0x766a0abb + W[37];
	t2 = e0(d) + Maj(d, e, f);
	g += t1;
	c = t1 + t2;
	t1 = b + e1(g) + Ch(g, h, a) + 0x81c2c92e + W[38];
	t2 = e0(c) + Maj(c, d, e);
	f += t1;
	b = t1 + t2;
	t1 = a + e1(f) + Ch(f, g, h) + 0x92722c85 + W[39];
	t2 = e0(b) + Maj(b, c, d);
	e += t1;
	a = t1 + t2;

	t1 = h + e1(e) + Ch(e, f, g) + 0xa2bfe8a1 + W[40];
	t2 = e0(a) + Maj(a, b, c);
	d += t1;
	h = t1 + t2;
	t1 = g + e1(d) + Ch(d, e, f) + 0xa81a664b + W[41];
	t2 = e0(h) + Maj(h, a, b);
	c += t1;
	g = t1 + t2;
	t1 = f + e1(c) + Ch(c, d, e) + 0xc24b8b70 + W[42];
	t2 = e0(g) + Maj(g, h, a);
	b += t1;
	f = t1 + t2;
	t1 = e + e1(b) + Ch(b, c, d) + 0xc76c51a3 + W[43];
	t2 = e0(f) + Maj(f, g, h);
	a += t1;
	e = t1 + t2;
	t1 = d + e1(a) + Ch(a, b, c) + 0xd192e819 + W[44];
	t2 = e0(e) + Maj(e, f, g);
	h += t1;
	d = t1 + t2;
	t1 = c + e1(h) + Ch(h, a, b) + 0xd6990624 + W[45];
	t2 = e0(d) + Maj(d, e, f);
	g += t1;
	c = t1 + t2;
	t1 = b + e1(g) + Ch(g, h, a) + 0xf40e3585 + W[46];
	t2 = e0(c) + Maj(c, d, e);
	f += t1;
	b = t1 + t2;
	t1 = a + e1(f) + Ch(f, g, h) + 0x106aa070 + W[47];
	t2 = e0(b) + Maj(b, c, d);
	e += t1;
	a = t1 + t2;

	t1 = h + e1(e) + Ch(e, f, g) + 0x19a4c116 + W[48];
	t2 = e0(a) + Maj(a, b, c);
	d += t1;
	h = t1 + t2;
	t1 = g + e1(d) + Ch(d, e, f) + 0x1e376c08 + W[49];
	t2 = e0(h) + Maj(h, a, b);
	c += t1;
	g = t1 + t2;
	t1 = f + e1(c) + Ch(c, d, e) + 0x2748774c + W[50];
	t2 = e0(g) + Maj(g, h, a);
	b += t1;
	f = t1 + t2;
	t1 = e + e1(b) + Ch(b, c, d) + 0x34b0bcb5 + W[51];
	t2 = e0(f) + Maj(f, g, h);
	a += t1;
	e = t1 + t2;
	t1 = d + e1(a) + Ch(a, b, c) + 0x391c0cb3 + W[52];
	t2 = e0(e) + Maj(e, f, g);
	h += t1;
	d = t1 + t2;
	t1 = c + e1(h) + Ch(h, a, b) + 0x4ed8aa4a + W[53];
	t2 = e0(d) + Maj(d, e, f);
	g += t1;
	c = t1 + t2;
	t1 = b + e1(g) + Ch(g, h, a) + 0x5b9cca4f + W[54];
	t2 = e0(c) + Maj(c, d, e);
	f += t1;
	b = t1 + t2;
	t1 = a + e1(f) + Ch(f, g, h) + 0x682e6ff3 + W[55];
	t2 = e0(b) + Maj(b, c, d);
	e += t1;
	a = t1 + t2;

	t1 = h + e1(e) + Ch(e, f, g) + 0x748f82ee + W[56];
	t2 = e0(a) + Maj(a, b, c);
	d += t1;
	h = t1 + t2;
	t1 = g + e1(d) + Ch(d, e, f) + 0x78a5636f + W[57];
	t2 = e0(h) + Maj(h, a, b);
	c += t1;
	g = t1 + t2;
	t1 = f + e1(c) + Ch(c, d, e) + 0x84c87814 + W[58];
	t2 = e0(g) + Maj(g, h, a);
	b += t1;
	f = t1 + t2;
	t1 = e + e1(b) + Ch(b, c, d) + 0x8cc70208 + W[59];
	t2 = e0(f) + Maj(f, g, h);
	a += t1;
	e = t1 + t2;
	t1 = d + e1(a) + Ch(a, b, c) + 0x90befffa + W[60];
	t2 = e0(e) + Maj(e, f, g);
	h += t1;
	d = t1 + t2;
	t1 = c + e1(h) + Ch(h, a, b) + 0xa4506ceb + W[61];
	t2 = e0(d) + Maj(d, e, f);
	g += t1;
	c = t1 + t2;
	t1 = b + e1(g) + Ch(g, h, a) + 0xbef9a3f7 + W[62];
	t2 = e0(c) + Maj(c, d, e);
	f += t1;
	b = t1 + t2;
	t1 = a + e1(f) + Ch(f, g, h) + 0xc67178f2 + W[63];
	t2 = e0(b) + Maj(b, c, d);
	e += t1;
	a = t1 + t2;

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
	state[4] += e;
	state[5] += f;
	state[6] += g;
	state[7] += h;

#if 0
	/* clear any sensitive info... */
	a = b = c = d = e = f = g = h = t1 = t2 = 0;
	memset(W, 0, 64 * sizeof(u32));
#endif
}

static void runhash(void *state, const void *input, const void *init) {
	memcpy(state, init, 32);
	sha256_transform(state, input);
}

const uint32_t sha256_init_state[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372,
		0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };





bool scanhash_c(struct thr_info*thr, const unsigned char *midstate,
		unsigned char *data, unsigned char *hash1, unsigned char *hash,
		const unsigned char *target, uint32_t max_nonce, uint32_t *last_nonce,
		uint32_t n) {
	uint32_t p[4];
	uint32_t first_n = n;
	uint32_t inter = (max_nonce - n);
	uint32_t *hash32 = (uint32_t *) hash;

	uint32_t *nonce = (uint32_t *) (data + 76);
	unsigned long stat_ctr = 0;
	char *m = malloc(128);

	uint32_t total = 0;
	data += 64;

	while (1) {

		/*
		// M1
		switch (nonce_block()) {
		case 1:
			*last_nonce = *nonce;
			return true;
		case 0:
			*last_nonce = *nonce;
			return false;
		}
*/
/*
		sprintf(m, "i:(%x:%x:%x:%x:%d;%d;%d;%d),n1:%x,n2:%x, h32_7:%x\n", p1,
				p2, p3, p4, s1, s2, s3, s4, nd, nu, hash32[7]);
		fputs(m, flog);
		fflush(flog);
*/
	}
	return false;
}

