/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/mem.h>
#include <gmssl/sm2.h>
#include <gmssl/sm3.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>

int sm2_fast_verify(const SM2_Z256_POINT point_table[16], const uint8_t dgst[32], const SM2_SIGNATURE *sig)
{
	SM2_Z256_POINT R;
	SM2_Z256_POINT T;
	sm2_z256_t r;
	sm2_z256_t s;
	sm2_z256_t e;
	sm2_z256_t x;
	sm2_z256_t t;

	// check r, s in [1, n-1]
	sm2_z256_from_bytes(r, sig->r);
	if (sm2_z256_is_zero(r) == 1) {
		error_print();
		return -1;
	}
	if (sm2_z256_cmp(r, sm2_z256_order()) >= 0) {
		error_print();
		return -1;
	}
	sm2_z256_from_bytes(s, sig->s);
	if (sm2_z256_is_zero(s) == 1) {
		error_print();
		return -1;
	}
	if (sm2_z256_cmp(s, sm2_z256_order()) >= 0) {
		error_print();
		return -1;
	}

	// t = r + s (mod n), check t != 0
	sm2_z256_modn_add(t, r, s);
	if (sm2_z256_is_zero(t)) {
		error_print();
		return -1;
	}

	// Q(x,y) = s * G + t * P
	sm2_z256_point_mul_generator(&R, s);
	sm2_z256_point_mul_ex(&T, t, point_table);
	sm2_z256_point_add(&R, &R, &T);
	sm2_z256_point_get_xy(&R, x, NULL);

	// e = H(M)
	sm2_z256_from_bytes(e, dgst);
	if (sm2_z256_cmp(e, sm2_z256_order()) >= 0) {
		sm2_z256_sub(e, e, sm2_z256_order());
	}

	// r' = e + x (mod n)
	if (sm2_z256_cmp(x, sm2_z256_order()) >= 0) {
		sm2_z256_sub(x, x, sm2_z256_order());
	}
	sm2_z256_modn_add(e, e, x);

	// check if r == r'
	if (sm2_z256_cmp(e, r) != 0) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_signature_from_der(SM2_SIGNATURE *sig, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const uint8_t *r;
	size_t rlen;
	const uint8_t *s;
	size_t slen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (asn1_integer_from_der(&r, &rlen, &d, &dlen) != 1
		|| asn1_integer_from_der(&s, &slen, &d, &dlen) != 1
		|| asn1_length_le(rlen, 32) != 1
		|| asn1_length_le(slen, 32) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	memset(sig, 0, sizeof(*sig));
	memcpy(sig->r + 32 - rlen, r, rlen);
	memcpy(sig->s + 32 - slen, s, slen);
	return 1;
}

int sm2_compute_z(uint8_t z[32], const SM2_Z256_POINT *pub, const char *id, size_t idlen)
{
	SM3_CTX ctx;
	uint8_t zin[18 + 32 * 6] = {
		0x00, 0x80,
		0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,
		0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFC,
		0x28,0xE9,0xFA,0x9E,0x9D,0x9F,0x5E,0x34,0x4D,0x5A,0x9E,0x4B,0xCF,0x65,0x09,0xA7,
		0xF3,0x97,0x89,0xF5,0x15,0xAB,0x8F,0x92,0xDD,0xBC,0xBD,0x41,0x4D,0x94,0x0E,0x93,
       		0x32,0xC4,0xAE,0x2C,0x1F,0x19,0x81,0x19,0x5F,0x99,0x04,0x46,0x6A,0x39,0xC9,0x94,
		0x8F,0xE3,0x0B,0xBF,0xF2,0x66,0x0B,0xE1,0x71,0x5A,0x45,0x89,0x33,0x4C,0x74,0xC7,
		0xBC,0x37,0x36,0xA2,0xF4,0xF6,0x77,0x9C,0x59,0xBD,0xCE,0xE3,0x6B,0x69,0x21,0x53,
		0xD0,0xA9,0x87,0x7C,0xC6,0x2A,0x47,0x40,0x02,0xDF,0x32,0xE5,0x21,0x39,0xF0,0xA0,
	};

	if (!z || !pub || !id) {
		error_print();
		return -1;
	}

	sm2_z256_point_to_bytes(pub, &zin[18 + 32 * 4]);

	sm3_init(&ctx);
	if (strcmp(id, SM2_DEFAULT_ID) == 0) {
		sm3_update(&ctx, zin, sizeof(zin));
	} else {
		uint8_t idbits[2];
		idbits[0] = (uint8_t)(idlen >> 5);
		idbits[1] = (uint8_t)(idlen << 3);
		sm3_update(&ctx, idbits, 2);
		sm3_update(&ctx, (uint8_t *)id, idlen);
		sm3_update(&ctx, zin + 18, 32 * 6);
	}
	sm3_finish(&ctx, z);
	return 1;
}

int sm2_verify_init(SM2_VERIFY_CTX *ctx, const SM2_KEY *key, const char *id, size_t idlen)
{
	if (!ctx || !key) {
		error_print();
		return -1;
	}

	sm3_init(&ctx->sm3_ctx);
	if (id) {
		uint8_t z[SM3_DIGEST_SIZE];

		if (idlen <= 0 || idlen > SM2_MAX_ID_LENGTH) {
			error_print();
			return -1;
		}
		sm2_compute_z(z, &key->public_key, id, idlen);
		sm3_update(&ctx->sm3_ctx, z, sizeof(z));
	}
	ctx->saved_sm3_ctx = ctx->sm3_ctx;

	if (sm2_key_set_public_key(&ctx->key, &key->public_key) != 1) {
		error_print();
		return -1;
	}

	sm2_z256_point_mul_pre_compute(&key->public_key, ctx->public_point_table);

	return 1;
}

int sm2_verify_update(SM2_VERIFY_CTX *ctx, const uint8_t *data, size_t datalen)
{
	if (!ctx) {
		error_print();
		return -1;
	}
	if (data && datalen > 0) {
		sm3_update(&ctx->sm3_ctx, data, datalen);
	}
	return 1;
}

int sm2_verify_finish(SM2_VERIFY_CTX *ctx, const uint8_t *sigbuf, size_t siglen)
{
	uint8_t dgst[SM3_DIGEST_SIZE];
	SM2_SIGNATURE sig;

	if (!ctx || !sigbuf) {
		error_print();
		return -1;
	}

	if (sm2_signature_from_der(&sig, &sigbuf, &siglen) != 1
		|| asn1_length_is_zero(siglen) != 1) {
		error_print();
		return -1;
	}

	sm3_finish(&ctx->sm3_ctx, dgst);

	if (sm2_fast_verify(ctx->public_point_table, dgst, &sig) != 1) {
		error_print();
		return -1;
	}

	return 1;
}

int sm2_verify_reset(SM2_VERIFY_CTX *ctx)
{
	ctx->sm3_ctx = ctx->saved_sm3_ctx;
	return 1;
}
