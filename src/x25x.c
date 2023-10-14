#include "x25x.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_gost.h"
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_shabal.h"
#include "sha3/sph_whirlpool.h"
#include "sha3/sph_sha2.h"
#include "sha3/sph_haval.h"
#include "sha3/sph_tiger.h"
#include "sha3/sph_panama.h"
#include "crypto/SWIFFTX/SWIFFTX.h"
#include "crypto/lyra2.h"
#include "crypto/lane.h"
#include "crypto/blake2.h"

void x25x_hash(const char* input, char* output, uint32_t len)
{
    sph_blake512_context     	ctx_blake;
    sph_bmw512_context       	ctx_bmw;
    sph_groestl512_context   	ctx_groestl;
	sph_jh512_context        	ctx_jh;
    sph_keccak512_context		ctx_keccak;
	sph_skein512_context		ctx_skein;
    sph_luffa512_context		ctx_luffa1;
    sph_cubehash512_context		ctx_cubehash1;
    sph_shavite512_context		ctx_shavite1;
    sph_simd512_context			ctx_simd1;
    sph_echo512_context			ctx_echo1;
    sph_hamsi512_context		ctx_hamsi1;
    sph_fugue512_context		ctx_fugue1;
    sph_shabal512_context       ctx_shabal1;
    sph_whirlpool_context       ctx_whirlpool1;
	sph_sha512_context       	ctx_sha2;
	sph_haval256_5_context		ctx_haval;
	sph_tiger_context 			ctx_tiger;
	sph_gost512_context			ctx_gost;
	sph_sha256_context			ctx_sha;
	sph_panama_context 			ctx_panama;

    //these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t hashA[25][16];

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, input, len);
    sph_blake512_close (&ctx_blake, &hashA[0]);

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, &hashA[0], 64);
    sph_bmw512_close(&ctx_bmw, &hashA[1]);

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, &hashA[1], 64);
    sph_groestl512_close(&ctx_groestl, &hashA[2]);

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, &hashA[2], 64);
    sph_skein512_close (&ctx_skein, &hashA[3]);

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, &hashA[3], 64);
    sph_jh512_close(&ctx_jh, &hashA[4]);

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, &hashA[4], 64);
    sph_keccak512_close(&ctx_keccak, &hashA[5]);

    sph_luffa512_init (&ctx_luffa1);
    sph_luffa512 (&ctx_luffa1, &hashA[5], 64);
    sph_luffa512_close (&ctx_luffa1, &hashA[6]);

    sph_cubehash512_init (&ctx_cubehash1);
    sph_cubehash512 (&ctx_cubehash1, &hashA[6], 64);
    sph_cubehash512_close(&ctx_cubehash1, &hashA[7]);

    sph_shavite512_init (&ctx_shavite1);
    sph_shavite512 (&ctx_shavite1, &hashA[7], 64);
    sph_shavite512_close(&ctx_shavite1, &hashA[8]);

    sph_simd512_init (&ctx_simd1);
    sph_simd512 (&ctx_simd1, &hashA[8], 64);
    sph_simd512_close(&ctx_simd1, &hashA[9]);

    sph_echo512_init (&ctx_echo1);
    sph_echo512 (&ctx_echo1, &hashA[9], 64);
    sph_echo512_close(&ctx_echo1, &hashA[10]);

    sph_hamsi512_init (&ctx_hamsi1);
    sph_hamsi512 (&ctx_hamsi1, &hashA[10], 64);
    sph_hamsi512_close(&ctx_hamsi1, &hashA[11]);

    sph_fugue512_init (&ctx_fugue1);
    sph_fugue512 (&ctx_fugue1, &hashA[11], 64);
    sph_fugue512_close(&ctx_fugue1, &hashA[12]);

	unsigned char temp[SWIFFTX_OUTPUT_BLOCK_SIZE] = {0};
    InitializeSWIFFTX();
    ComputeSingleSWIFFTX(&hashA[12], temp, false);

    sph_shabal512_init (&ctx_shabal1);
    sph_shabal512 (&ctx_shabal1, &hashA[12], 64);
    sph_shabal512_close(&ctx_shabal1, &hashA[13]);

    sph_whirlpool_init (&ctx_whirlpool1);
    sph_whirlpool (&ctx_whirlpool1, &hashA[13], 64);
    sph_whirlpool_close(&ctx_whirlpool1, &hashA[14]);

	sph_sha512_init(&ctx_sha2);
    sph_sha512 (&ctx_sha2, &hashA[14], 64);
    sph_sha512_close(&ctx_sha2, &hashA[15]);

	memcpy((unsigned char*)&hashA[16], temp, 64);

    sph_haval256_5_init(&ctx_haval);
    sph_haval256_5 (&ctx_haval, &hashA[16], 64);
    sph_haval256_5_close(&ctx_haval, &hashA[17]);

    sph_tiger_init(&ctx_tiger);
    sph_tiger (&ctx_tiger, &hashA[17], 64);
    sph_tiger_close(&ctx_tiger, &hashA[18]);

    LYRA2(&hashA[19], 32, &hashA[18], 32, &hashA[18], 32, 1, 4, 4);

    sph_gost512_init(&ctx_gost);
    sph_gost512 (&ctx_gost, &hashA[19], 64);
    sph_gost512_close(&ctx_gost, &hashA[20]);

    sph_sha256_init(&ctx_sha);
    sph_sha256 (&ctx_sha, &hashA[20], 64);
    sph_sha256_close(&ctx_sha, &hashA[21]);

 	sph_panama_init(&ctx_gost);
    sph_panama (&ctx_gost, &hashA[21], 64);
    sph_panama_close(&ctx_gost, &hashA[22]);

	laneHash(512, (BitSequence*)&hashA[22], 512, (BitSequence*)&hashA[23]);

	// simple shuffle algorithm
	#define X25X_SHUFFLE_BLOCKS (24 /* number of algos so far */ * 64 /* output bytes per algo */ / 2 /* block size */)
	#define X25X_SHUFFLE_ROUNDS 12
	static const uint16_t x25x_round_const[X25X_SHUFFLE_ROUNDS] = {
		0x142c, 0x5830, 0x678c, 0xe08c,
		0x3c67, 0xd50d, 0xb1d8, 0xecb2,
		0xd7ee, 0x6783, 0xfa6c, 0x4b9c
	};

	uint16_t* block_pointer = (uint16_t*)hashA;
	for (int r = 0; r < X25X_SHUFFLE_ROUNDS; r++) {
		for (int i = 0; i < X25X_SHUFFLE_BLOCKS; i++) {
			uint16_t block_value = block_pointer[X25X_SHUFFLE_BLOCKS - i - 1];
			block_pointer[i] ^= block_pointer[block_value % X25X_SHUFFLE_BLOCKS] + (x25x_round_const[r] << (i % 16));
		}
	}

    blake2s_simple((uint8_t*)&hashA[24], &hashA[0], 64 * 24);

    memcpy(output, &hashA[24], 32);
}
