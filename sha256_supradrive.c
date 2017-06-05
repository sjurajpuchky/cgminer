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
 * * 12.1.2014 Fixed and modified for SupraDrive algo
 * Copyright (c) Juraj Puchk� - Devtech <sjurajpuchky@devtech.cz>
 * Optimized for OMP 4.2.2014
 *
 */

#include "config.h"

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "miner.h"
#include "bitshared.h"

#define PI 3.14159265

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

const uint32_t sd_sha256_init_state[8] = {
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19 };

uint32_t supradrive_currentupnonce[6];
uint32_t supradrive_currentdownnonce[6];
semiResult semiResultBuffer[MAX_SEMI_RESULT_BUFF_SIZE];
uint32_t supradrive_total = 0;
uint32_t semiResults = 0;
uint32_t foundResults = 0;

typedef uint32_t (*genStrategy_func)(uint32_t nonce, uint32_t max_nonce, uint32_t *total);

extern uint32_t c_strategyIRandom(uint32_t nonce, uint32_t max_nonce, uint32_t *total);
extern uint32_t c_strategyRandom(uint32_t nonce, uint32_t max_nonce, uint32_t *total);
extern uint32_t c_strategyDRandom(uint32_t nonce, uint32_t max_nonce, uint32_t *total);
extern uint32_t c_strategyNRandom(uint32_t nonce, uint32_t max_nonce, uint32_t *total);
extern uint32_t c_strategyIncrement(uint32_t nonce, uint32_t max_nonce, uint32_t *total);
extern uint32_t c_strategyDecrement(uint32_t nonce, uint32_t max_nonce, uint32_t *total);
extern uint32_t c_strategySine(uint32_t nonce, uint32_t max_nonce, uint32_t *total);
extern uint32_t c_strategyCosine(uint32_t nonce, uint32_t max_nonce, uint32_t *total);
extern uint32_t c_strategyBlock(uint32_t nonce, uint32_t max_nonce, uint32_t *total);
extern uint32_t c_strategyRBlock(uint32_t nonce, uint32_t max_nonce, uint32_t *total);
extern uint32_t c_strategyPhase(uint32_t nonce, uint32_t max_nonce, uint32_t *total);
extern uint32_t c_strategyRPhase(uint32_t nonce, uint32_t max_nonce, uint32_t *total);

#define countStrategies 6
enum genDownCityStrategy {
	ST_INCREMENT,
	ST_SINE,
	ST_PHASE,
	ST_BLOCK,
	ST_IRANDOM,
	ST_RANDOM
};

enum genUpCityStrategy {
	ST_DECREMENT,
	ST_COSINE,
	ST_RPHASE,
	ST_RBLOCK,
	ST_DRANDOM,
	ST_NRANDOM
};

const unsigned char *strategyUpTitle[] = {
		[ST_INCREMENT] = "In:",
		[ST_SINE ] = "Si:",
		[ST_PHASE] = "Ph:",
		[ST_BLOCK ] = "Bl:",
		[ST_IRANDOM] = "Ir:",
		[ST_RANDOM] = "Ra:" };

const unsigned char *strategyDownTitle[] = {
		[ST_DECREMENT ] = "De:",
		[ST_COSINE ] = "Co:",
		[ST_RPHASE] = "Rp:",
		[ST_RBLOCK] = "Rb:",
		[ST_DRANDOM ] = "Dr:",
		[ST_NRANDOM] = "Nr:" };

genStrategy_func downCityStrategies[] = {
		[ST_INCREMENT ] = (genStrategy_func) c_strategyIncrement,
		[ST_SINE] = (genStrategy_func) c_strategySine,
		[ST_PHASE] = (genStrategy_func) c_strategyPhase,
		[ST_BLOCK] = (genStrategy_func) c_strategyBlock,
		[ST_IRANDOM ] = (genStrategy_func) c_strategyIRandom,
		[ST_RANDOM] = (genStrategy_func) c_strategyRandom };

genStrategy_func upCityStrategies[] = {
		[ST_DECREMENT ] = (genStrategy_func) c_strategyDecrement,
		[ST_COSINE] = (genStrategy_func) c_strategyCosine,
		[ST_RPHASE ] = (genStrategy_func) c_strategyRPhase,
		[ST_RBLOCK] = (genStrategy_func) c_strategyRBlock,
		[ST_DRANDOM ] = (genStrategy_func) c_strategyDRandom,
		[ST_NRANDOM] = (genStrategy_func) c_strategyNRandom };

// Tools
bool fulltest_omp(const unsigned char *hash, const unsigned char *target);

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
//#pragma omp parallel for
	for (i = 0; i < 16; i++)
		LOAD_OP(i, W, input);

	/* now blend */
//#pragma omp parallel for
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
}

char *bin2hex_omp(const unsigned char *p, size_t len) {
	unsigned int i;
	ssize_t slen;
	char *s;

	slen = len * 2 + 1;
	if (slen % 4)
		slen += 4 - (slen % 4);
	s = calloc(slen, 1);
	if (unlikely(!s))
		quit(1, "Failed to calloc in bin2hex");
//#pragma omp parallel for
	for (i = 0; i < len; i++)
		sprintf(s + (i * 2), "%02x", (unsigned int) p[i]);

	return s;
}

static inline void swap256_omp(void *dest_p, const void *src_p) {
	uint32_t *dest = dest_p;
	const uint32_t *src = src_p;

	dest[0] = src[7];
	dest[1] = src[6];
	dest[2] = src[5];
	dest[3] = src[4];
	dest[4] = src[3];
	dest[5] = src[2];
	dest[6] = src[1];
	dest[7] = src[0];

}

bool fulltest_omp(const unsigned char *hash, const unsigned char *target) {
	unsigned char hash_swap[32], target_swap[32];
	uint32_t *hash32 = (uint32_t *) hash_swap;
	uint32_t *target32 = (uint32_t *) target_swap;
	char *hash_str, *target_str;
	bool rc = true;
	int i;

	swap256_omp(hash_swap, hash);
	swap256_omp(target_swap, target);

//#pragma omp prallel for
	for (i = 0; i < 32 / 4; i++) {
		uint32_t h32tmp = htobe32(hash32[i]);
		uint32_t t32tmp = htole32(target32[i]);

		target32[i] = swab32(target32[i]); /* for printing */

		if (h32tmp > t32tmp) {
			rc = false;
			break;
		}
		if (h32tmp < t32tmp) {
			rc = true;
			break;
		}
	}

	if (opt_debug) {
		hash_str = bin2hex_omp(hash_swap, 32);
		target_str = bin2hex_omp(target_swap, 32);

		applog(LOG_DEBUG, " Proof: %s\nTarget: %s\nTrgVal? %s", hash_str, target_str,
				rc ? "YES (hash <= target)" : "no (false positive; hash > target)");

		free(hash_str);
		free(target_str);
	}

	return rc;
}

nonceLookupStatus nonce_lookup(struct thr_info*thr, const unsigned char *midstate, unsigned char *data, unsigned char *hash1,
		unsigned char *hash, const unsigned char *target, uint32_t max_nonce, uint32_t *nonce, uint32_t *total) {

	uint32_t *hash32 = (uint32_t *) hash;

	memcpy(hash1, midstate, 32);
	memcpy(hash, sd_sha256_init_state, 32);

	sha256_transform(hash1, data);
	sha256_transform(hash, hash1);

	if (hash32[7] == 0) {
		addSemiResult(nonce, hash, target, &onSemiResultsAreFull);
		return NL_SUCCESS;
	}

	if ((*total >= max_nonce) || thr->work_restart) {
		if (thr->work_restart) {
 			 unlockAllNonces(max_nonce);
			*total = 0;
			return NL_RESTART;
		}
		 unlockAllNonces(max_nonce);
		*total = 0;
		return NL_COMPLETE;
	}

	return NL_INPROGRESS;
}
/* suspiciously similar to ScanHash* from bitcoin */
uint32_t _nonceUp[countStrategies];
uint32_t _nonceDown[countStrategies];

bool scanhash_supradrive(struct thr_info *thr, const unsigned char *midstate, unsigned char *data, unsigned char *hash1,
		unsigned char *hash, const unsigned char *target, uint32_t max_nonce, uint32_t *last_nonce, uint32_t n) {
	uint32_t first_n = n;
	uint32_t *hash32 = (uint32_t *) hash;
	uint32_t *nonce = (uint32_t *) (data + 76);

	_nonceUp[ST_INCREMENT] = *last_nonce;
	_nonceUp[ST_SINE] = *last_nonce;
	_nonceUp[ST_PHASE] = *last_nonce;
	_nonceUp[ST_BLOCK] = *last_nonce;
	_nonceUp[ST_IRANDOM] = *last_nonce;
	_nonceUp[ST_RANDOM] = *last_nonce;

	_nonceDown[ST_DECREMENT] = max_nonce;
	_nonceDown[ST_COSINE] = max_nonce;
	_nonceDown[ST_RPHASE] = max_nonce;
	_nonceDown[ST_RBLOCK] = max_nonce;
	_nonceDown[ST_DRANDOM] = max_nonce;
	_nonceDown[ST_NRANDOM] = max_nonce;

	unlockAllNonces(max_nonce);
	unsigned long stat_ctr = 0;

	supradrive_total = n;
	foundResults = 0;
	removeSemiResults();
	// data += 64;
	int strategy;
	int selector = 0;
	log_notice("Supradrive started max_nonce %08x", max_nonce);
	while (1) {
		for (strategy = 0; strategy < countStrategies; strategy++) {
			_nonceUp[strategy] = (*upCityStrategies[strategy])(_nonceUp[strategy], max_nonce, &supradrive_total);
			if (isNonceLocked(_nonceUp[strategy]) == false) {
				supradrive_currentupnonce[strategy] = _nonceUp[strategy];
				*nonce = _nonceUp[strategy];
				// lockNonce(*nonce);
				switch (nonce_lookup(thr, midstate, data, hash1, hash, target, nonce, max_nonce, &supradrive_total)) {
				case NL_SUCCESS:
					log_notice("Found semi result %x at %d semi results %d", *nonce, supradrive_total, foundResults);
					break;
				case NL_RESTART:
					log_notice("Restarted at %d semi results %d", supradrive_total, foundResults);
					if (foundResults > 0) {
						cleanUpSemiResults();
						return true;
					} else {
						return false;
					}
					break;
				case NL_COMPLETE:
					log_notice("Complete at %d semi results %d", supradrive_total, foundResults);
					if (foundResults > 0) {
						cleanUpSemiResults();
						return true;
					} else {
						return false;
					}
					break;
				}
				*last_nonce = *nonce;
			}

			_nonceDown[strategy] = (*downCityStrategies[strategy])(_nonceDown[strategy], max_nonce, &supradrive_total);
			if (isNonceLocked(_nonceDown[strategy]) == false) {
				supradrive_currentdownnonce[strategy] = _nonceDown[strategy];
				*nonce = _nonceDown[strategy];
				// lockNonce(*nonce);
				switch (nonce_lookup(thr, midstate, data, hash1, hash, target, nonce, max_nonce, &supradrive_total)) {
				case NL_SUCCESS:
					log_notice("Found semi result %x at %d semi results %d", *nonce, supradrive_total, foundResults);
					break;
				case NL_RESTART:
					log_notice("Restarted at %d semi results %d", supradrive_total, foundResults);
					if (foundResults > 0) {
						cleanUpSemiResults();
						return true;
					} else {
						return false;
					}
					break;
				case NL_COMPLETE:
					log_notice("Complete at %d semi results %d", supradrive_total, foundResults);
					if (foundResults > 0) {
						cleanUpSemiResults();
						return true;
					} else {
						return false;
					}
					break;
				}
				*last_nonce = *nonce;
			}
		}
	}
	return false;
}

uint32_t c_strategyIncrement(uint32_t nonce, uint32_t max_nonce, uint32_t *total) {
	*total += 1;
	nonce += 1;
	if (nonce >= max_nonce) {
		nonce = 0;
	}
	return nonce;
}

uint32_t c_strategySine(uint32_t nonce, uint32_t max_nonce, uint32_t *total) {
	*total += 1;
	//nonce = (uint32_t) (max_nonce * abs(sin((*total % 180) * PI / 180)));
	return nonce;
}

uint32_t c_strategyPhase(uint32_t nonce, uint32_t max_nonce, uint32_t *total) {
	*total += 1;
	//int i = *total % countSelector;
	//unsigned char segment = (unsigned char) selectSegment32_8(nonce,i) * abs(sin(*total % 360));
	//nonce = combineSegment32_8(nonce,i,segment);
	//if (nonce >= max_nonce) {
	//	nonce = combineSegment32_8(0,i,segment);
	//}
	return nonce;
}

uint32_t c_strategyBlock(uint32_t nonce, uint32_t max_nonce, uint32_t *total) {
	*total += 1;
	nonce += 0xF;
	if (nonce >= max_nonce) {
		nonce = 0;
	}
	return nonce;
}

uint32_t c_strategyDecrement(uint32_t nonce, uint32_t max_nonce, uint32_t *total) {
	*total += 1;
	nonce -= 1;
	if (nonce <= 0) {
		nonce = max_nonce;
	}
	return nonce;
}

uint32_t c_strategyCosine(uint32_t nonce, uint32_t max_nonce, uint32_t *total) {
	*total += 1;
	//nonce = (uint32_t) (max_nonce * abs(cos((*total % 360) * PI / 360)));
	return nonce;
}
uint32_t c_strategyRPhase(uint32_t nonce, uint32_t max_nonce, uint32_t *total) {
	*total += 1;
	nonce = max_nonce;
	return nonce;
}
uint32_t c_strategyRBlock(uint32_t nonce, uint32_t max_nonce, uint32_t *total) {
	*total += 1;
	nonce -= 0xF;
	return nonce;
}

uint32_t c_strategyIRandom(uint32_t nonce, uint32_t max_nonce, uint32_t *total) {
	*total += 1;
	nonce += rand() % 0xFF;
	return nonce;
}
uint32_t c_strategyRandom(uint32_t nonce, uint32_t max_nonce, uint32_t *total) {
	*total += 1;
	nonce = (uint32_t) (rand() % max_nonce);
	return nonce;
}
uint32_t c_strategyDRandom(uint32_t nonce, uint32_t max_nonce, uint32_t *total) {
	*total += 1;
	int i = *total % countSelector;
	unsigned char segment = rand() % 0xFF;
	nonce = combineSegment32_8(nonce,i,segment);
	if (nonce >= max_nonce) {
		nonce = combineSegment32_8(0,i,segment);
	}
	return nonce;
}
uint32_t c_strategyNRandom(uint32_t nonce, uint32_t max_nonce, uint32_t *total) {
	*total += 1;
	nonce = max_nonce - (rand() % max_nonce);
	return nonce;
}
