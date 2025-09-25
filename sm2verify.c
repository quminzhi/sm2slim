/*
 *  Copyright 2014-2024 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>
#include <gmssl/x509.h>


static const char *usage = "(-pubkey pem | -cert pem) [-id str] [-in file] -sig file";

static const char *options =
"\n"
"Options\n"
"\n"
"    -pubkey pem         Signer's public key file in PEM format\n"
"    -cert pem           Signer's certificate in PEM format\n"
"    -id str             Signer's identity string, '1234567812345678' by default\n"
"    -in file | stdin    Signed file or data\n"
"    -sig file           Signature in binary DER encoding\n"
"\n"
"Examples\n"
"\n"
"    $ gmssl sm2keygen -pass P@ssw0rd -out sm2.pem -pubout sm2pub.pem\n"
"    $ echo -n 'message to be signed' | gmssl sm2sign -key sm2.pem -pass P@ssw0rd -out sm2.sig\n"
"    $ echo -n 'message to be signed' | gmssl sm2verify -pubkey sm2pub.pem -sig sm2.sig\n"
"\n";


int sm2verify(char* pubkeyfile, char* infile, char* sigfile)
{
	int ret = 1;
	char *id = SM2_DEFAULT_ID;
	FILE *pubkeyfp = NULL;
	FILE *infp = stdin;
	FILE *sigfp = NULL;
	SM2_KEY key;
	SM2_VERIFY_CTX verify_ctx;
	uint8_t buf[4096];
	size_t len;
	uint8_t sig[SM2_MAX_SIGNATURE_SIZE];
	size_t siglen;
	int vr;

	if (!pubkeyfile || !infile || !sigfile) {
		if (!pubkeyfile)
			fprintf(stderr, "sm2verify: '-pubkey pubkeyfile' required\n");
		if (!infile)
			fprintf(stderr, "sm2verify: '-in infile' required\n");
		if (!sigfile)
			fprintf(stderr, "sm2verify: '-in sigfile' required\n");
		goto end;
	}

	if (!(pubkeyfp = fopen(pubkeyfile, "rb"))) {
		fprintf(stderr, "open '%s' failure : %s\n", pubkeyfile, strerror(errno));
		goto end;
	}
	if (!(infp = fopen(infile, "rb"))) {
		fprintf(stderr, "open '%s' failure : %s\n", infile, strerror(errno));
		goto end;
	}
	if (!(sigfp = fopen(sigfile, "rb"))) {
		fprintf(stderr, "open '%s' failure : %s\n", sigfile, strerror(errno));
		goto end;
	}

	if ((siglen = fread(sig, 1, sizeof(sig), sigfp)) <= 0) {
		fprintf(stderr, "read signature error : %s\n", strerror(errno));
		goto end;
	}
	if (sm2_public_key_info_from_pem(&key, pubkeyfp) != 1) {
		fprintf(stderr, "parse public key failed\n");
		goto end;
	}

	if (sm2_verify_init(&verify_ctx, &key, id, strlen(id)) != 1) {
		fprintf(stderr, "sm2_verify_init: inner error\n");
		goto end;
	}
	while ((len = fread(buf, 1, sizeof(buf), infp)) > 0) {
		if (sm2_verify_update(&verify_ctx, buf, len) != 1) {
			fprintf(stderr, "sm2_verify_update: inner error\n");
			goto end;
		}
	}
	if ((vr = sm2_verify_finish(&verify_ctx, sig, siglen)) < 0) {
		fprintf(stderr, "sm2_verify_finish: inner error\n");
		goto end;
	}

	fprintf(stdout, "verify : %s\n", vr == 1 ? "success" : "failure");
	if (vr == 1) {
		ret = 0;
	}

end:
	if (infile && infp) fclose(infp);
	if (pubkeyfp) fclose(pubkeyfp);
	if (sigfp) fclose(sigfp);
	return ret;
}

int main(int argc, char **argv)
{
	char *prog = argv[0];
	char *id = SM2_DEFAULT_ID;
	char *pubkeyfile = NULL;
	char *certfile = NULL;
	char *infile = NULL;
	char *sigfile = NULL;
	int vr;

	argc--;
	argv++;
	if (argc < 1) {
		fprintf(stderr, "usage: gmssl %s %s\n", prog, usage);
		return 1;
	}

	while (argc > 0) {
		if (!strcmp(*argv, "-help")) {
			printf("usage: gmssl %s %s\n", prog, usage);
			printf("%s\n", options);
		} else if (!strcmp(*argv, "-pubkey")) {
			if (certfile) {
				fprintf(stderr, "gmssl %s: options '-pubkey' '-cert' conflict\n", prog);
			}
			if (--argc < 1) goto bad;
			pubkeyfile = *(++argv);
		} else if (!strcmp(*argv, "-cert")) {
			if (pubkeyfile) {
				fprintf(stderr, "gmssl %s: options '-pubkey' '-cert' conflict\n", prog);
			}
			if (--argc < 1) goto bad;
			certfile = *(++argv);
		} else if (!strcmp(*argv, "-id")) {
			if (--argc < 1) goto bad;
			id = *(++argv);
		} else if (!strcmp(*argv, "-in")) {
			if (--argc < 1) goto bad;
			infile = *(++argv);
		} else if (!strcmp(*argv, "-sig")) {
			if (--argc < 1) goto bad;
			sigfile = *(++argv);
		} else {
			fprintf(stderr, "gmssl %s: illegal option '%s'\n", prog, *argv);
bad:
			fprintf(stderr, "gmssl %s: '%s' option value missing\n", prog, *argv);
		}

		argc--;
		argv++;
	}

	sm2verify(pubkeyfile, infile, sigfile);
	return 0;
}
