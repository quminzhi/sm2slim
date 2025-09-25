#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <gmssl/sm2verify.h>


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

int main(int argc, char **argv)
{
	char *prog = argv[0];
	char *id = "1234567812345678";
	char *pubkeyfile = NULL;
	char *certfile = NULL;
	char *infile = NULL;
	char *sigfile = NULL;

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
