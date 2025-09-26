/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


// https://www.obj-sys.com/asn1tutorial/node128.html

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <limits.h>
#include <time.h>
#include <ctype.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>
#include <gmssl/endian.h>


static const char *asn1_tag_index[] = {
	"[0]",  "[1]",  "[2]",  "[3]",  "[4]",  "[5]",  "[6]",  "[7]",  "[8]",  "[9]",
	"[10]", "[11]", "[12]", "[13]", "[14]", "[15]", "[16]", "[17]", "[18]", "[19]",
	"[20]", "[21]", "[22]", "[23]", "[24]", "[25]", "[26]", "[27]", "[28]", "[29]",
	"[30]", "[31]",
};

// not in-use
int asn1_tag_is_cstring(int tag)
{
	switch (tag) {
	case ASN1_TAG_UTF8String:
	case ASN1_TAG_NumericString:
	case ASN1_TAG_PrintableString:
	case ASN1_TAG_TeletexString:
	case ASN1_TAG_IA5String:
	case ASN1_TAG_GeneralString:
		return 1;
	}
	return 0;
}

int format_print(FILE *fp, int format, int indent, const char *str, ...)
{
	va_list args;
	int i;
	for (i = 0; i < indent; i++) {
		fprintf(fp, " ");
	}
	va_start(args, str);
	vfprintf(fp, str, args);
	va_end(args);
	return 1;
}

int asn1_object_identifier_print(FILE *fp, int format, int indent, const char *label, const char *name,
	const uint32_t *nodes, size_t nodes_cnt)
{
	size_t i;
	format_print(fp, format, indent, "%s: %s", label, name ? name : "(unknown)");
	if (nodes) {
		fprintf(fp, " (");
		for (i = 0; i < nodes_cnt - 1; i++) {
			fprintf(fp, "%d.", (int)nodes[i]);
		}
		fprintf(fp, "%d)", nodes[i]);
	}
	fprintf(fp, "\n");
	return 1;
}

int asn1_null_from_der(const uint8_t **in, size_t *inlen)
{
	if (!in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	// tag
	if (*inlen == 0 || **in != ASN1_TAG_NULL) {
		return 0;
	}
	(*in)++;
	(*inlen)--;

	// value
	if (*inlen < 1) {
		error_print();
		return -1;
	}
	if (**in != 0x00) {
		error_print();
		return -1;
	}
	(*in)++;
	(*inlen)--;
	return 1;
}

int asn1_length_to_der(size_t len, uint8_t **out, size_t *outlen)
{
	if (len > INT_MAX) {
		error_print();
		return -1;
	}
	if (!outlen) {
		error_print();
		return -1;
	}

	if (len < 128) {
		if (out && *out) {
			*(*out)++ = (uint8_t)len;
		}
		(*outlen)++;

	} else {
		uint8_t buf[4];
		int nbytes;

		if (len < 256) nbytes = 1;
		else if (len < 65536) nbytes = 2;
		else if (len < (1 << 24)) nbytes = 3;
		else nbytes = 4;
		PUTU32(buf, (uint32_t)len);

		if (out && *out) {
			*(*out)++ = 0x80 + nbytes;
			memcpy(*out, buf + 4 - nbytes, nbytes);
			(*out) += nbytes;
		}
		(*outlen) += 1 + nbytes;
	}
	return 1;
}

int asn1_length_from_der(size_t *len, const uint8_t **in, size_t *inlen)
{
	if (!len || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	if (*inlen == 0) {
		error_print();
		return -1;
	}

	if (**in < 128) {
		*len = *(*in)++;
		(*inlen)--;

	} else {
		uint8_t buf[4] = {0};
		size_t nbytes  = *(*in)++ & 0x7f;
		(*inlen)--;

		if (nbytes < 1 || nbytes > 4) {
			error_print();
			return -1;
		}
		if (*inlen < nbytes) {
			error_print();
			return -1;
		}
		// make sure length is not in BER long presentation
		if (nbytes == 1 && **in < 0x80) {
			error_print();
			return -1;
		}
		if (nbytes > 1 && **in == 0) {
			error_print();
			return -1;
		}

		memcpy(buf + 4 - nbytes, *in, nbytes);
		*len = (size_t)GETU32(buf);
		*in += nbytes;
		*inlen -= nbytes;
	}

	// check if the left input is enough for reading (d,dlen)
	if (*inlen < *len) {
		error_print();
		return -2; // Special error for test_asn1_length() // TODO: fix asn1test.c test vector 			
	}
	return 1;
}

int asn1_type_from_der(int tag, const uint8_t **d, size_t *dlen, const uint8_t **in, size_t *inlen)
{
	if (!d || !dlen || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	// tag
	if (*inlen == 0 || **in != tag) {
		*d = NULL;
		*dlen = 0;
		return 0;
	}
	(*in)++;
	(*inlen)--;

	// length
	if (asn1_length_from_der(dlen, in, inlen) != 1) {
		error_print();
		return -1;
	}

	// data
	*d = *in;
	*in += *dlen;
	*inlen -= *dlen;
	return 1;
}

int asn1_integer_from_der_ex(int tag, const uint8_t **a, size_t *alen, const uint8_t **in, size_t *inlen)
{
	size_t len;

	if (!a || !alen || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	// tag
	if (*inlen == 0 || **in != tag) {
		*a = NULL;
		*alen = 0;
		return 0;
	}
	(*in)++;
	(*inlen)--;

	// length (not zero)
	if (asn1_length_from_der(&len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (len == 0) {
		error_print();
		return -1;
	}

	// check if ASN1_INTEGER is negative
	if (**in & 0x80) {
		error_print();
		return -1;
	}

	// remove leading zero
	if (**in == 0 && len > 1) {
		(*in)++;
		(*inlen)--;
		len--;

		// the following bit should be one
		if (((**in) & 0x80) == 0) {
			error_print();
			return -1;
		}
	}

	// no leading zeros
	if (**in == 0 && len > 1) {
		error_print();
		return -1;
	}

	// return integer bytes
	*a = *in;
	*alen = len;
	*in += len;
	*inlen -= len;

	return 1;
}

int asn1_bit_string_to_der_ex(int tag, const uint8_t *bits, size_t nbits, uint8_t **out, size_t *outlen)
{
	size_t nbytes = (nbits + 7) / 8;
	size_t unused_nbits = nbytes * 8 - nbits;

	if (!outlen) {
		error_print();
		return -1;
	}

	if (!bits) {
		if (nbits) {
			error_print();
			return -1;
		}
		return 0;
	}

	// tag
	if (out && *out) {
		*(*out)++ = tag;
	}
	(*outlen)++;

	// length
	(void)asn1_length_to_der(nbytes + 1, out, outlen);

	// unused num of bits
	if (out && *out) {
		*(*out)++ = (uint8_t)unused_nbits;
	}
	(*outlen)++;

	// bits
	if (out && *out) {
		memcpy(*out, bits, nbytes);
		*out += nbytes;
	}
	*outlen += nbytes;

	return 1;
}

int asn1_bit_string_from_der_ex(int tag, const uint8_t **bits, size_t *nbits, const uint8_t **in, size_t *inlen)
{
	size_t len;
	int unused_bits;

	if (!bits || !nbits || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	// tag
	if (*inlen == 0 || **in != tag) {
		*bits = NULL;
		*nbits = 0;
		return 0;
	}
	(*in)++;
	(*inlen)--;

	// length (min == 2)
	if (asn1_length_from_der(&len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (len < 2) {
		error_print();
		return -1;
	}

	// unused_bits counter
	unused_bits = **in;
	if (unused_bits > 7) {
		error_print();
		return -1;
	}
	(*in)++;
	(*inlen)--;
	len--;

	// return bits
	*bits = *in;
	*nbits = (len << 3) - unused_bits;
	*in += len;
	*inlen -= len;

	return 1;
}

int asn1_bit_octets_to_der_ex(int tag, const uint8_t *octs, size_t nocts, uint8_t **out, size_t *outlen)
{
	int ret;
	if ((ret = asn1_bit_string_to_der_ex(tag, octs, nocts << 3, out, outlen)) != 1) {
		if (ret) error_print();
		return ret;
	}
	return 1;
}

int asn1_bit_octets_from_der_ex(int tag, const uint8_t **octs, size_t *nocts, const uint8_t **in, size_t *inlen)
{
	int ret;
	const uint8_t *bits;
	size_t nbits;

	if (!octs || !nocts) {
		error_print();
		return -1;
	}

	if ((ret = asn1_bit_string_from_der_ex(tag, &bits, &nbits, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else {
			*octs = NULL;
			*nocts = 0;
		}
		return ret;
	}

	if (nbits % 8) {
		error_print();
		return -1;
	}
	*octs = bits;
	*nocts = nbits >> 3;
	return 1;
}

static void asn1_oid_node_to_base128(uint32_t a, uint8_t **out, size_t *outlen)
{
	uint8_t buf[5];
	int n = 0;

	buf[n++] = a & 0x7f;
	a >>= 7;

	while (a) {
		buf[n++] = 0x80 | (a & 0x7f);
		a >>= 7;
	}

	while (n--) {
		if (out && *out) {
			*(*out)++ = buf[n];
		}
		(*outlen)++;
	}
}

static int asn1_oid_node_from_base128(uint32_t *a, const uint8_t **in, size_t *inlen)
{
	uint8_t buf[5];
	int n = 0;
	int i;

	for (;;) {
		if ((*inlen)-- < 1 || n >= 5) {
			error_print();
			return -1;
		}
		buf[n] = *(*in)++;
		if ((buf[n++] & 0x80) == 0) {
			break;
		}
	}

	// 32 - 7*4 = 4, so the first byte should be like 1000bbbb
	if (n == 5 && (buf[0] & 0x70)) {
		error_print();
		return -1;
	}

	*a = 0;
	for (i = 0; i < n; i++) {
		*a = ((*a) << 7) | (buf[i] & 0x7f);
	}

	return 1;
}

int asn1_object_identifier_from_octets(uint32_t *nodes, size_t *nodes_cnt, const uint8_t *in, size_t inlen)
{
	if (!nodes_cnt || !in || !inlen) {
		error_print();
		return -1;
	}

	if (nodes) {
		*nodes++ = (*in) / 40;
		*nodes++ = (*in) % 40;
	}
	in++;
	inlen--;
	*nodes_cnt = 2;

	while (inlen) {
		uint32_t val;
		if (*nodes_cnt > ASN1_OID_MAX_NODES) {
			error_print();
			return -1;
		}
		if (asn1_oid_node_from_base128(&val, &in, &inlen) < 0) {
			error_print();
			return -1;
		}
		if (nodes) {
			*nodes++ = val;
		}
		(*nodes_cnt)++;
	}

	return 1;
}

int asn1_object_identifier_from_der_ex(int tag, uint32_t *nodes, size_t *nodes_cnt,
	const uint8_t **in, size_t *inlen)
{
	size_t len;

	// unlike _from_octets(), _from_der() require output buffer
	if (!nodes || !nodes_cnt || !in || !(*in) || !inlen) {
		error_print();
		return -1;
	}

	// tag
	if (*inlen == 0 || **in != tag) {
		*nodes_cnt = 0;
		return 0;
	}
	(*in)++;
	(*inlen)--;

	// length (not zero)
	if (asn1_length_from_der(&len, in, inlen) != 1) {
		error_print();
		return -1;
	}
	if (len < ASN1_OID_MIN_OCTETS) {
		error_print();
		return -1;
	}

	// parse OID
	if (asn1_object_identifier_from_octets(nodes, nodes_cnt, *in, len) != 1) {
		error_print();
		return -1;
	}
	*in += len;
	*inlen -= len;

	return 1;
}

int asn1_oid_info_from_der_ex(const ASN1_OID_INFO **info, uint32_t *nodes, size_t *nodes_cnt,
	const ASN1_OID_INFO *infos, size_t infos_cnt, const uint8_t **in, size_t *inlen)
{
	int ret;
	size_t i;

	if (!info) {
		error_print();
		return -1;
	}
	if ((ret = asn1_object_identifier_from_der(nodes, nodes_cnt, in, inlen)) != 1) {
		if (ret < 0) error_print();
		else *info = NULL;
		return ret;
	}

	for (i = 0; i < infos_cnt; i++) {
		if (*nodes_cnt == infos[i].nodes_cnt
			&& memcmp(nodes, infos[i].nodes, (*nodes_cnt) * sizeof(int)) == 0) {
			*info = &infos[i];
			return 1;
		}
	}

	// OID with correct encoding but in the (infos, infos_cnt) list
	*info = NULL;
	return 1;
}

int asn1_oid_info_from_der(const ASN1_OID_INFO **info, const ASN1_OID_INFO *infos, size_t count, const uint8_t **in, size_t *inlen)
{
	int ret;
	uint32_t nodes[ASN1_OID_MAX_NODES];
	size_t nodes_cnt;

	if ((ret = asn1_oid_info_from_der_ex(info, nodes, &nodes_cnt, infos, count, in, inlen)) != 1) {
		if (ret < 0) error_print();
		return ret;
	}
	if (*info == NULL) {
		asn1_object_identifier_print(stderr, 0, 0, "Unknown OID", NULL, nodes, nodes_cnt);
		error_print();
		return -1;
	}
	return 1;
}

int asn1_length_is_zero(size_t len)
{
	if (len) {
		error_print();
		return -1;
	}
	return 1;
}

int asn1_length_le(size_t len1, size_t len2)
{
	if (len1 > len2) {
		error_print();
		format_print(stderr, 0, 0, "%s: %zu <= %zu failed\n", __FUNCTION__, len1, len2);
		return -1;
	}
	return 1;
}
