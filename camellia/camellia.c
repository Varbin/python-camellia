/*
	camellia.c version 1.0.0
	Copyright (c) 2013

 * NTT (Nippon Telegraph and Telephone Corporation) . All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer as
 *   the first lines of this file unmodified.
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NTT ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL NTT BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */


/*
	uint8_t subkey[26][8] should be allocated if key length is 128 bits,
	otherwise uint8_t subkey[34][8] should be allocated.

	The key schedule function is:
	void camelliaKS(const unsigned keyLen, const uint8_t key[], uint8_t subkey[][8]);

	The one block encryption and decryption function is:
	void camellia(const int mode, const unsigned keyLen, const uint8_t pt[16], const uint8_t subkey[][8], uint8_t ct[16]);
	mode is 0 for encryption, and mode is 1 for decryption.
	subkey is intended to be computed by camelliaKS()
	before calling camellia() function.
 */

/*
	Algorithm Specification
    https://info.isl.ntt.co.jp/crypt/eng/camellia/specifications.html
 */


#include<inttypes.h>						/* only used for uint8_t type */
#include<string.h>							/* prototype for memset() and memcpy() */


/* sbox */
static const uint8_t s[256] = {
	0x70, 0x82, 0x2c, 0xec, 0xb3, 0x27, 0xc0, 0xe5,
	0xe4, 0x85, 0x57, 0x35, 0xea, 0x0c, 0xae, 0x41,
	0x23, 0xef, 0x6b, 0x93, 0x45, 0x19, 0xa5, 0x21,
	0xed, 0x0e, 0x4f, 0x4e, 0x1d, 0x65, 0x92, 0xbd,
	0x86, 0xb8, 0xaf, 0x8f, 0x7c, 0xeb, 0x1f, 0xce,
	0x3e, 0x30, 0xdc, 0x5f, 0x5e, 0xc5, 0x0b, 0x1a,
	0xa6, 0xe1, 0x39, 0xca, 0xd5, 0x47, 0x5d, 0x3d,
	0xd9, 0x01, 0x5a, 0xd6, 0x51, 0x56, 0x6c, 0x4d,
	0x8b, 0x0d, 0x9a, 0x66, 0xfb, 0xcc, 0xb0, 0x2d,
	0x74, 0x12, 0x2b, 0x20, 0xf0, 0xb1, 0x84, 0x99,
	0xdf, 0x4c, 0xcb, 0xc2, 0x34, 0x7e, 0x76, 0x05,
	0x6d, 0xb7, 0xa9, 0x31, 0xd1, 0x17, 0x04, 0xd7,
	0x14, 0x58, 0x3a, 0x61, 0xde, 0x1b, 0x11, 0x1c,
	0x32, 0x0f, 0x9c, 0x16, 0x53, 0x18, 0xf2, 0x22,
	0xfe, 0x44, 0xcf, 0xb2, 0xc3, 0xb5, 0x7a, 0x91,
	0x24, 0x08, 0xe8, 0xa8, 0x60, 0xfc, 0x69, 0x50,
	0xaa, 0xd0, 0xa0, 0x7d, 0xa1, 0x89, 0x62, 0x97,
	0x54, 0x5b, 0x1e, 0x95, 0xe0, 0xff, 0x64, 0xd2,
	0x10, 0xc4, 0x00, 0x48, 0xa3, 0xf7, 0x75, 0xdb,
	0x8a, 0x03, 0xe6, 0xda, 0x09, 0x3f, 0xdd, 0x94,
	0x87, 0x5c, 0x83, 0x02, 0xcd, 0x4a, 0x90, 0x33,
	0x73, 0x67, 0xf6, 0xf3, 0x9d, 0x7f, 0xbf, 0xe2,
	0x52, 0x9b, 0xd8, 0x26, 0xc8, 0x37, 0xc6, 0x3b,
	0x81, 0x96, 0x6f, 0x4b, 0x13, 0xbe, 0x63, 0x2e,
	0xe9, 0x79, 0xa7, 0x8c, 0x9f, 0x6e, 0xbc, 0x8e,
	0x29, 0xf5, 0xf9, 0xb6, 0x2f, 0xfd, 0xb4, 0x59,
	0x78, 0x98, 0x06, 0x6a, 0xe7, 0x46, 0x71, 0xba,
	0xd4, 0x25, 0xab, 0x42, 0x88, 0xa2, 0x8d, 0xfa,
	0x72, 0x07, 0xb9, 0x55, 0xf8, 0xee, 0xac, 0x0a,
	0x36, 0x49, 0x2a, 0x68, 0x3c, 0x38, 0xf1, 0xa4,
	0x40, 0x28, 0xd3, 0x7b, 0xbb, 0xc9, 0x43, 0xc1,
	0x15, 0xe3, 0xad, 0xf4, 0x77, 0xc7, 0x80, 0x9e
};

/* key schedule constants */
static const uint8_t Sigma[6][8] = {
	{0xa0, 0x9e, 0x66, 0x7f, 0x3b, 0xcc, 0x90, 0x8b},
	{0xb6, 0x7a, 0xe8, 0x58, 0x4c, 0xaa, 0x73, 0xb2},
	{0xc6, 0xef, 0x37, 0x2f, 0xe9, 0x4f, 0x82, 0xbe},
	{0x54, 0xff, 0x53, 0xa5, 0xf1, 0xd3, 0x6f, 0x1c},
	{0x10, 0xe5, 0x27, 0xfa, 0xde, 0x68, 0x2d, 0x1d},
	{0xb0, 0x56, 0x88, 0xc2, 0xb3, 0xe6, 0xc1, 0xfd}
};


/* s2(x) = s1(x) <<< 1, s3(x) = s1(x) >>> 1, s4(x) = s1(x <<< 1) */
#define s1(x) s[x]
#define s2(x) ((s[x] << 1) + (s[x] >> 7))
#define s3(x) ((s[x] << 7) + (s[x] >> 1))
#define s4(x) s[(uint8_t)(((x) << 1) + ((x) >> 7))]


/*
	Auxiliary functions
*/

/* dst[] <- src1[] ^ src2[] */
static void xorOctets(const unsigned nOctets, const uint8_t src1[], const uint8_t src2[], uint8_t dst[]){
	int i;

	for(i=0; i<nOctets; i++){
		dst[i] = src1[i] ^ src2[i];
	}
}



/* a[] <-> b[] */
static void	swapHalfBlock(uint8_t a[8], uint8_t b[8]){
	unsigned i;
	uint8_t t;

	for(i=0; i<8; i++){
		t = a[i];
		a[i] = b[i];
		b[i] = t;
	}
}



/* dst[] <- src1[] & src2[] */
static void and4octets(const uint8_t src1[4], const uint8_t src2[4], uint8_t dst[4]){
	int i;

	for(i=0; i<4; i++){
		dst[i] = src1[i] & src2[i];
	}
}



/* dst[] <- src1[] | src2[] */
static void or4octets(const uint8_t src1[4], const uint8_t src2[4], uint8_t dst[4]){
	int i;

	for(i=0; i<4; i++){
		dst[i] = src1[i] | src2[i];
	}
}


/* x[] <<<= 1 */
static void rot1(unsigned nOctets, uint8_t x[]){
	uint8_t x0;
	int i;

	x0 = x[0];
	nOctets --;
	for(i=0; i<nOctets; i++){
		x[i] = (x[i] << 1) ^ (x[i + 1] >> 7);
	}
	x[nOctets] = (x[nOctets] << 1) ^ (x0 >> 7);
}


/* rotate 128-bit data to the left by 16 bits */
static void rot16(uint8_t x[16]){
	uint8_t x0 = x[0], x1 = x[1];
	int i;

	for(i=0; i<14; i++){
		x[i] = x[i + 2];
	}
	x[i++] = x0;
	x[i] = x1;
}



/* rotate 128-bit data to the left by 15 bits */
static void rot15(uint8_t x[16]){
	uint8_t x15;
	int i;

	rot16(x);
	x15 = x[15];
	for(i=15; i>=1; i--){
		x[i] = (x[i] >> 1) ^ (x[i - 1] << 7);
	}
	x[0] = (x[0] >> 1) ^ (x15 << 7);
}



/* rotate 128-bit data to the left by 17 bits */
static void rot17(uint8_t x[16]){
	rot16(x);
	rot1(16, x);
}



/* Camellia round function without swap */
static void CamelliaRound(const uint8_t subkey[8], const uint8_t l[8], uint8_t r[8]){
	uint8_t t[8], a;

	/* key XOR */
	xorOctets(8, subkey, l, t);

	/* S-Function */
	t[0] = s1(t[0]);
	t[1] = s2(t[1]);
	t[2] = s3(t[2]);
	t[3] = s4(t[3]);
	t[4] = s2(t[4]);
	t[5] = s3(t[5]);
	t[6] = s4(t[6]);
	t[7] = s1(t[7]);

	/* P-Function with Feistel XOR */
	a = t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6]; r[7] ^= a;
	a ^= t[0] ^ t[1] ^ t[2]; r[3] ^= a;
	a ^= t[1] ^ t[6] ^ t[7]; r[6] ^= a;
	a ^= t[0] ^ t[1] ^ t[3]; r[2] ^= a;
	a ^= t[0] ^ t[5] ^ t[6]; r[5] ^= a;
	a ^= t[0] ^ t[2] ^ t[3]; r[1] ^= a;
	a ^= t[3] ^ t[4] ^ t[5]; r[4] ^= a;
	a ^= t[1] ^ t[2] ^ t[3]; r[0] ^= a;
}



/* Camellia FL function */
static void CamelliaFL(const uint8_t subkey[8], uint8_t x[8]){
	uint8_t t[4];

	and4octets(&x[0], &subkey[0], t);
	rot1(4, t);
	xorOctets(4, t, &x[4], &x[4]);
	or4octets(&x[4], &subkey[4], t);
	xorOctets(4, &x[0], t, &x[0]);
}



/* Camellia FL^{-1} function */
static void CamelliaFLinv(const uint8_t subkey[8], uint8_t y[8]){
	uint8_t t[4];

	or4octets(&y[4], &subkey[4], t);
	xorOctets(4, &y[0], t, &y[0]);
	and4octets(&y[0], &subkey[0], t);
	rot1(4, t);
	xorOctets(4, t, &y[4], &y[4]);
}



/*
	Camellia key schedule
	subkey[26] should be allocated for keyLen == 128.
	otherwise subkey[34] should be allocated.
*/
void camelliaKS(const unsigned keyLen, const uint8_t key[], uint8_t subkey[][8]){
	uint8_t ikey[4][16];					/* 0...KL, 1...KR, 2...KA, 3...KB */
	uint8_t *pl, *pr, *p;
	int aki;											/* all intermediate key index */
	int dki;											/* drop key index */
	int ski;											/* subkey index */
	int maxikey;
	int i, j;
	static int drop128[] = {
		8, 9, 15, 16, 22, 23, 0
	};
	static int drop256[] = {
		2, 3, 4, 5, 8, 9, 14, 15, 16, 17, 20, 21, 26, 27, 30, 31,
		36, 37, 42, 43, 46, 47, 48, 49, 54, 55, 58, 59, 60, 61, 0
	};
	int *drop;										/* pointer to drop128[] or drop256[] */

	/* padding */
	memset(&ikey[1], 0, 16);
	memcpy(&ikey[0], key, keyLen / 8);
	if(keyLen == 192){
		for(i=0; i<8; i++){
			ikey[1][i + 8] = ~ikey[1][i];
		}
	}

	/* generate intermediate keys KA, KB */
	pl = &ikey[2][0];	pr = &ikey[2][8];
	for(i=0; i<4; i++){
		if((i % 2) == 0){
			xorOctets(16, ikey[i / 2 + 1], ikey[0], ikey[2]);
		}
		CamelliaRound(Sigma[i], pl, pr);
		p = pl; pl = pr; pr = p;
	}

	if(keyLen != 128){
		xorOctets(16, ikey[2], ikey[1], ikey[3]); /* KB <- KA ^ KR */
		CamelliaRound(Sigma[4], &ikey[3][0], &ikey[3][8]);
		CamelliaRound(Sigma[5], &ikey[3][8], &ikey[3][0]);
	}

	/* subkey generation */
	aki = dki = ski = 0;
	if(keyLen == 128){
		maxikey = 2;
		drop = drop128;
		memcpy(ikey[1], ikey[2], 16); /* ikey[1] is KA for 128-bit key */
	}
	else{													/* keyLen == 192 or 256 */
		maxikey = 4;
		drop = drop256;
	}
	for(i=0; i<8; i++){
		for(j=0; j<2*maxikey; j++){
			if(aki != drop[dki]){
				memcpy(subkey[ski ++], &ikey[j / 2][(j % 2) * 8], 8);
			}
			else{
				dki ++;
			}
			aki ++;
		}
		for(j=0; j<maxikey; j++){
			if(i < 4){
				rot15(ikey[j]);
			}
			else{
				rot17(ikey[j]);
			}
		}
	}
}



/* Camellia one block encryption (mode == 0) / decryption (mode == 1) */
void camellia(const int mode, const unsigned keyLen, const uint8_t pt[16], const uint8_t subkey[][8], uint8_t ct[16]){
	int r;												/* round */
	int ski;											/* subkey index */
	int direction;

	if(mode == 0){								/* encryption */
		direction = 1;
		ski = 0;
	}
	else{													/* decryption */
		direction = -1;
		ski = (keyLen == 128) ? (26 - 2) : (34 - 2);
	}

	/* prewhitening */
	xorOctets(16, pt, subkey[ski], ct);
	if(mode == 0){								/* encryption */
		ski += 2;
	}
	else{													/* decryption */
		ski --;
	}

	/* main iteration */
	for(r=0; r<24; r+=2){
		if((keyLen == 128) && (r >= 18)){
			break;
		}
		if((r == 6) || (r == 12) || (r == 18)){
			CamelliaFL(subkey[ski], &ct[0]); ski += direction;
			CamelliaFLinv(subkey[ski], &ct[8]); ski += direction;
		}
		CamelliaRound(subkey[ski], &ct[0], &ct[8]); ski += direction;
		CamelliaRound(subkey[ski], &ct[8], &ct[0]); ski += direction;
	}
	swapHalfBlock(&ct[0], &ct[8]);

	/* postwhitening */
	if(mode)ski--;
	xorOctets(16, ct, subkey[ski], ct);
}
