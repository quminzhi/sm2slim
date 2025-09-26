/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/ec.h>
#include <gmssl/error.h>


#define oid_sm_scheme 1,2,156,10197,1
static uint32_t oid_sm2[] = { oid_sm_scheme,301 };

#define oid_x9_62_curves oid_x9_62,3
#define oid_x9_62_prime_curves oid_x9_62_curves,1
static uint32_t oid_prime192v1[] = { oid_x9_62_prime_curves,1 };
static uint32_t oid_prime256v1[] = { oid_x9_62_prime_curves,7 }; // NIST P-256

#define oid_secg_curve 1,3,132,0
static uint32_t oid_secp256k1[] = { oid_secg_curve,10 };
static uint32_t oid_secp384r1[] = { oid_secg_curve,34 }; // NIST P-384
static uint32_t oid_secp521r1[] = { oid_secg_curve,35 }; // NIST P-521


static const ASN1_OID_INFO ec_named_curves[] = {
	{ OID_sm2, "sm2p256v1", oid_sm2, sizeof(oid_sm2)/sizeof(int), 0, "SM2" },
	{ OID_prime192v1, "prime192v1", oid_prime192v1, sizeof(oid_prime192v1)/sizeof(int), 0, },
	{ OID_prime256v1, "prime256v1", oid_prime256v1, sizeof(oid_prime256v1)/sizeof(int), 0, "NIST P-256" },
	{ OID_secp256k1, "secp256k1", oid_secp256k1, sizeof(oid_secp256k1)/sizeof(int) },
	{ OID_secp384r1, "secp384r1", oid_secp384r1, sizeof(oid_secp384r1)/sizeof(int), 0, "NIST P-384" },
	{ OID_secp521r1, "secp521r1", oid_secp521r1, sizeof(oid_secp521r1)/sizeof(int), 0, "NIST P-521" }
};

static const int ec_named_curves_count =
	sizeof(ec_named_curves)/sizeof(ec_named_curves[0]);

int ec_named_curve_from_der(int *oid, const uint8_t **in, size_t *inlen)
{
	int ret;
	const ASN1_OID_INFO *info;
	if ((ret = asn1_oid_info_from_der(&info, ec_named_curves, ec_named_curves_count, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *oid = -1;
		return ret;
	}
	*oid = info->oid;
	return 1;
}