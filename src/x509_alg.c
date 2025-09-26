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
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/x509_alg.h>


// static uint32_t oid_sm3[] = { 1,2,156,10197,1,401 };
// static uint32_t oid_md5[] = { 1,2,840,113549,2,5 };
// static uint32_t oid_sha1[] = { 1,3,14,3,2,26 };
// static uint32_t oid_sha256[] = { 2,16,840,1,101,3,4,2,1 };
// static uint32_t oid_sha384[] = { 2,16,840,1,101,3,4,2,2 };
// static uint32_t oid_sha512[] = { 2,16,840,1,101,3,4,2,3 };
// static uint32_t oid_sha224[] = { 2,16,840,1,101,3,4,2,4 };

// static const ASN1_OID_INFO x509_digest_algors[] = {
// 	{ OID_sm3, "sm3", oid_sm3, sizeof(oid_sm3)/sizeof(int) },
// 	{ OID_md5, "md5", oid_md5, sizeof(oid_md5)/sizeof(int) },
// 	{ OID_sha1, "sha1", oid_sha1, sizeof(oid_sha1)/sizeof(int) },
// 	{ OID_sha224, "sha224", oid_sha224, sizeof(oid_sha224)/sizeof(int) },
// 	{ OID_sha256, "sha256", oid_sha256, sizeof(oid_sha256)/sizeof(int) },
// 	{ OID_sha384, "sha384", oid_sha384, sizeof(oid_sha384)/sizeof(int) },
// 	{ OID_sha512, "sha512", oid_sha512, sizeof(oid_sha512)/sizeof(int) },
// };

// static const int x509_digest_algors_count =
// 	sizeof(x509_digest_algors)/sizeof(x509_digest_algors[0]);

// static uint32_t oid_sm4_cbc[] =  { 1,2,156,10197,1,104,2 };
// static uint32_t oid_aes128_cbc[] = { 2,16,840,1,101,3,4,1,2 };
// static uint32_t oid_aes192_cbc[] = { 2,16,840,1,101,3,4,1,22 };
// static uint32_t oid_aes256_cbc[] = { 2,16,840,1,101,3,4,1,42 };

// static const ASN1_OID_INFO x509_enc_algors[] = {
// 	{ OID_sm4_cbc, "sm4-cbc", oid_sm4_cbc, sizeof(oid_sm4_cbc)/sizeof(int) },
// 	{ OID_aes128_cbc, "aes128-cbc", oid_aes128_cbc, sizeof(oid_aes128_cbc)/sizeof(int) },
// 	{ OID_aes192_cbc, "aes192-cbc", oid_aes192_cbc, sizeof(oid_aes192_cbc)/sizeof(int) },
// 	{ OID_aes256_cbc, "aes256-cbc", oid_aes256_cbc, sizeof(oid_aes256_cbc)/sizeof(int) },
// };

// static const int x509_enc_algors_count =
// 	sizeof(x509_enc_algors)/sizeof(x509_enc_algors[0]);

// static uint32_t oid_sm2sign_with_sm3[] = { 1,2,156,10197,1,501 };
// static uint32_t oid_rsasign_with_sm3[] = { 1,2,156,10197,1,504 };
// static uint32_t oid_ecdsa_with_sha1[] = { 1,2,840,10045,4,1 };
// static uint32_t oid_ecdsa_with_sha224[] = { 1,2,840,10045,4,3,1 };
// static uint32_t oid_ecdsa_with_sha256[] = { 1,2,840,10045,4,3,2 };
// static uint32_t oid_ecdsa_with_sha384[] = { 1,2,840,10045,4,3,3 };
// static uint32_t oid_ecdsa_with_sha512[] = { 1,2,840,10045,4,3,4 };
// static uint32_t oid_rsasign_with_md5[] = { 1,2,840,113549,1,1,4 };
// static uint32_t oid_rsasign_with_sha1[] = { 1,2,840,113549,1,1,5 };
// static uint32_t oid_rsasign_with_sha224[] = { 1,2,840,113549,1,1,14 };
// static uint32_t oid_rsasign_with_sha256[] = { 1,2,840,113549,1,1,11 };
// static uint32_t oid_rsasign_with_sha384[] = { 1,2,840,113549,1,1,12 };
// static uint32_t oid_rsasign_with_sha512[] = { 1,2,840,113549,1,1,13 };


// /*
// from RFC 3447 Public-Key Cryptography Standards (PKCS) #1: RSA Cryptography
//                       Specifications Version 2.1

//   Appendix C. ASN.1 module

//   -- When rsaEncryption is used in an AlgorithmIdentifier the
//   -- parameters MUST be present and MUST be NULL.

//   -- When the following OIDs are used in an AlgorithmIdentifier the
//   -- parameters MUST be present and MUST be NULL.
//   --
//   md2WithRSAEncryption       OBJECT IDENTIFIER ::= { pkcs-1 2 }
//   md5WithRSAEncryption       OBJECT IDENTIFIER ::= { pkcs-1 4 }
//   sha1WithRSAEncryption      OBJECT IDENTIFIER ::= { pkcs-1 5 }
//   sha256WithRSAEncryption    OBJECT IDENTIFIER ::= { pkcs-1 11 }
//   sha384WithRSAEncryption    OBJECT IDENTIFIER ::= { pkcs-1 12 }
//   sha512WithRSAEncryption    OBJECT IDENTIFIER ::= { pkcs-1 13 }

// from RFC 3279 Algorithms and Identifiers for the
//                 Internet X.509 Public Key Infrastructure
//        Certificate and Certificate Revocation List (CRL) Profile

//    2.2.3 ECDSA Signature Algorithm

//    When the ecdsa-with-SHA1 algorithm identifier appears as the
//    algorithm field in an AlgorithmIdentifier, the encoding MUST omit the
//    parameters field.  That is, the AlgorithmIdentifier SHALL be a
//    SEQUENCE of one component: the OBJECT IDENTIFIER ecdsa-with-SHA1.


// from RFC 5754 Using SHA2 Algorithms with Cryptographic Message Syntax

//    3.3.  ECDSA

//    When any of these four object identifiers appears within an
//                      ^ ecdsa-with-SHA224/SHA256/SHA384/SHA512
//    AlgorithmIdentifier, the parameters field MUST be absent.  That is,
//    the AlgorithmIdentifier SHALL be a SEQUENCE of one component: the OID
//    ecdsa-with-SHA224, ecdsa-with-SHA256, ecdsa-with-SHA384, or ecdsa-
//    with-SHA512.


// from RFC 5758 Internet X.509 Public Key Infrastructure:
//         Additional Algorithms and Identifiers for DSA and ECDSA

//    3.1.  DSA Signature Algorithm

//    When the id-dsa-with-sha224 or id-dsa-with-sha256 algorithm
//    identifier appears in the algorithm field as an AlgorithmIdentifier,
//    the encoding SHALL omit the parameters field.  That is, the
//    AlgorithmIdentifier SHALL be a SEQUENCE of one component, the OID id-
//    dsa-with-sha224 or id-dsa-with-sha256.

//    3.2.  ECDSA Signature Algorithm

//    When the ecdsa-with-SHA224, ecdsa-with-SHA256, ecdsa-with-SHA384, or
//    ecdsa-with-SHA512 algorithm identifier appears in the algorithm field
//    as an AlgorithmIdentifier, the encoding MUST omit the parameters
//    field.  That is, the AlgorithmIdentifier SHALL be a SEQUENCE of one
//    component, the OID ecdsa-with-SHA224, ecdsa-with-SHA256, ecdsa-with-
//    SHA384, or ecdsa-with-SHA512.

// */

// #ifdef ENABLE_SM2_ALGOR_ID_ENCODE_NULL // from CMakeLists.txt
// #define SM2_SIGN_ALGOR_FLAGS 1
// #else
// #define SM2_SIGN_ALGOR_FLAGS 0
// #endif

// static const ASN1_OID_INFO x509_sign_algors[] = {
// 	{ OID_sm2sign_with_sm3, "sm2sign-with-sm3", oid_sm2sign_with_sm3, sizeof(oid_sm2sign_with_sm3)/sizeof(int), SM2_SIGN_ALGOR_FLAGS },
// 	{ OID_rsasign_with_sm3, "rsasign-with-sm3", oid_rsasign_with_sm3, sizeof(oid_rsasign_with_sm3)/sizeof(int), 1 },
// 	{ OID_ecdsa_with_sha1, "ecdsa-with-sha1", oid_ecdsa_with_sha1, sizeof(oid_ecdsa_with_sha1)/sizeof(int), 0 },
// 	{ OID_ecdsa_with_sha224, "ecdsa-with-sha224", oid_ecdsa_with_sha224, sizeof(oid_ecdsa_with_sha224)/sizeof(int), 0 } ,
// 	{ OID_ecdsa_with_sha256, "ecdsa-with-sha256", oid_ecdsa_with_sha256, sizeof(oid_ecdsa_with_sha256)/sizeof(int), 0 },
// 	{ OID_ecdsa_with_sha384, "ecdsa-with-sha384", oid_ecdsa_with_sha384, sizeof(oid_ecdsa_with_sha384)/sizeof(int), 0 },
// 	{ OID_ecdsa_with_sha512, "ecdsa-with-sha512", oid_ecdsa_with_sha512, sizeof(oid_ecdsa_with_sha512)/sizeof(int), 0 },
// 	{ OID_rsasign_with_md5, "md5WithRSAEncryption", oid_rsasign_with_md5, sizeof(oid_rsasign_with_md5)/sizeof(int), 0 },
// 	{ OID_rsasign_with_sha1, "sha1WithRSAEncryption", oid_rsasign_with_sha1, sizeof(oid_rsasign_with_sha1)/sizeof(int), 0 },
// 	{ OID_rsasign_with_sha224, "sha224WithRSAEncryption", oid_rsasign_with_sha224, sizeof(oid_rsasign_with_sha224)/sizeof(int), 1 },
// 	{ OID_rsasign_with_sha256, "sha256WithRSAEncryption", oid_rsasign_with_sha256, sizeof(oid_rsasign_with_sha256)/sizeof(int), 1 },
// 	{ OID_rsasign_with_sha384, "sha384WithRSAEncryption", oid_rsasign_with_sha384, sizeof(oid_rsasign_with_sha384)/sizeof(int), 1 },
// 	{ OID_rsasign_with_sha512, "sha512WithRSAEncryption", oid_rsasign_with_sha512, sizeof(oid_rsasign_with_sha512)/sizeof(int), 1 },
// };

// static const int x509_sign_algors_count =
// 	sizeof(x509_sign_algors)/sizeof(x509_sign_algors[0]);

// /*
// sm2encrypt: no parameters

// rsaes_oaep: from rfc 3560
// RSAES-OAEP-params  ::=  SEQUENCE  {
// 	hashFunc    [0] AlgorithmIdentifier DEFAULT sha1Identifier,
// 	maskGenFunc [1] AlgorithmIdentifier DEFAULT mgf1SHA1Identifier,
// 	pSourceFunc [2] AlgorithmIdentifier DEFAULT
// */

// static uint32_t oid_sm2encrypt[] = { 1,2,156,10197,1,301,2 };
static uint32_t oid_rsa_encryption[] = { 1,2,840,113549,1,1,1 };
// static uint32_t oid_rsaes_oaep[] = { 1,2,840,113549,1,1,7 };

// static const ASN1_OID_INFO x509_pke_algors[] = {
// 	{ OID_sm2encrypt, "sm2encrypt", oid_sm2encrypt, sizeof(oid_sm2encrypt)/sizeof(int) },
// 	{ OID_rsa_encryption, "rsaEncryption", oid_rsa_encryption, sizeof(oid_rsa_encryption)/sizeof(int) },
// 	{ OID_rsaes_oaep, "rsaesOAEP", oid_rsaes_oaep, sizeof(oid_rsaes_oaep)/sizeof(int) },
// };

// static const int x509_pke_algors_count =
// 	sizeof(x509_pke_algors)/sizeof(x509_pke_algors[0]);

static uint32_t oid_ec_public_key[] = { oid_x9_62,2,1 };

static const ASN1_OID_INFO x509_public_key_algors[] = {
	{ OID_ec_public_key, "ecPublicKey", oid_ec_public_key, sizeof(oid_ec_public_key)/sizeof(int), 0, "X9.62 ecPublicKey" },
	{ OID_rsa_encryption, "rsaEncryption", oid_rsa_encryption, sizeof(oid_rsa_encryption)/sizeof(int), 0, "RSAEncryption" },
};

static const int x509_public_key_algors_count =
	sizeof(x509_public_key_algors)/sizeof(x509_public_key_algors[0]);

int x509_public_key_algor_from_der(int *oid , int *curve_or_null, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *d;
	size_t dlen;
	const ASN1_OID_INFO *info;

	if ((ret = asn1_sequence_from_der(&d, &dlen, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}

	if (asn1_oid_info_from_der(&info, x509_public_key_algors, x509_public_key_algors_count, &d, &dlen) != 1) {
		error_print();
		return -1;
	}
	*oid = info->oid;

	switch (*oid) {
	case OID_ec_public_key:
		if (ec_named_curve_from_der(curve_or_null, &d, &dlen) != 1
			|| asn1_length_is_zero(dlen) != 1) {
			error_print();
			return -1;
		}
		break;
	case OID_rsa_encryption:
		if ((*curve_or_null = asn1_null_from_der(&d, &dlen)) < 0
			|| asn1_length_is_zero(dlen) != 1) {
			error_print();
			return -1;
		}
		break;
	default:
		error_print();
		return -1;
	}
	return 1;
}
