#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2.h>

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