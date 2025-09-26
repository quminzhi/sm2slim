/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <string.h>
#include <gmssl/sm2_z256.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/pem.h>
#include <gmssl/sm3.h>
#include <gmssl/sm4.h>
#include <gmssl/rand.h>
#include <gmssl/pkcs8.h>
#include <gmssl/error.h>
#include <gmssl/ec.h>
#include <gmssl/mem.h>
#include <gmssl/x509_alg.h>

int sm2_public_key_algor_from_der(const uint8_t **in, size_t *inlen)
{
	int ret;
	int oid;
	int curve;

	if ((ret = x509_public_key_algor_from_der(&oid, &curve, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (oid != OID_ec_public_key) {
		error_print();
		return -1;
	}
	if (curve != OID_sm2) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_key_set_public_key(SM2_KEY *key, const SM2_Z256_POINT *public_key)
{
	if (!key || !public_key) {
		error_print();
		return -1;
	}

	key->public_key = *public_key;
	sm2_z256_set_zero(key->private_key);

	return 1;
}

int sm2_public_key_from_der(SM2_KEY *key, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_bit_octets_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (dlen != 65) {
		error_print();
		return -1;
	}

	if (sm2_z256_point_from_octets(&key->public_key, d, dlen) != 1) {
		error_print();
		return -1;
	}
	sm2_z256_set_zero(key->private_key);

	return 1;
}

int sm2_public_key_info_from_der(SM2_KEY *pub_key, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (sm2_public_key_algor_from_der(&d, &dlen) != 1
		|| sm2_public_key_from_der(pub_key, &d, &dlen) != 1
		|| asn1_length_is_zero(dlen) != 1) {
		error_print();
		return -1;
	}
	return 1;
}

int sm2_public_key_info_from_pem(SM2_KEY *a, FILE *fp)
{
	uint8_t buf[512];
	const uint8_t *cp = buf;
	size_t len;

	if (pem_read(fp, "PUBLIC KEY", buf, &len, sizeof(buf)) != 1) {
		error_print();
		return -1;
	}
	if (sm2_public_key_info_from_der(a, &cp, &len) != 1
		|| asn1_length_is_zero(len) != 1) {
		error_print();
		return -1;
	}
	return 1;
}
