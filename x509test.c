/* Test of various x509 API calls in OpenSSL for later use with rdesktop */

#include <stdio.h>
#include <openssl/x509v3.h>

int
main(int argc, char **argv)
{
	X509 *cacert, *cert;
	char *cacertfilename;
	char *certfilename;
	FILE *cacertfile;
	FILE *certfile;
	FILE *stdout_FILE;
	RSA *pubkey;
	EVP_PKEY *epk = NULL;
	int cert_type = 0;
	int certstatus = -1;

	X509_STORE *ctx = NULL;
	X509_STORE_CTX *csc;
	X509_LOOKUP *lookup = NULL;

	if (argc < 3)
	{
		printf("Usage: %s <cacertfile> <certfile>\n", argv[0]);
		return 1;
	}

	cacertfilename = argv[1];
	certfilename = argv[2];

	cacertfile = fopen(cacertfilename, "r");
	if (NULL == cacertfile)
	{
		perror(cacertfilename);
		return 2;
	}
	certfile = fopen(certfilename, "r");
	if (NULL == certfile)
	{
		perror(certfilename);
		fclose(cacertfile);
		return 3;
	}

	cacert = d2i_X509_fp(cacertfile, NULL);
	if (NULL == cacert)
	{
		printf("Failed to load %s into a X509 structure", cacertfilename);
	}

	cert = d2i_X509_fp(certfile, NULL);
	if (NULL == cert)
	{
		printf("Failed to load %s into a X509 structure", certfilename);
	}

	ctx = X509_STORE_new();

	//  lookup=X509_STORE_add_lookup(ctx,X509_LOOKUP_file());
	//  X509_LOOKUP_load_file(lookup,"w2k3cert_ca.pem",X509_FILETYPE_PEM);
	X509_STORE_add_cert(ctx, cacert);

	csc = X509_STORE_CTX_new();
	X509_STORE_CTX_init(csc, ctx, cert, NULL);
	certstatus = X509_verify_cert(csc);


	printf("X509_verify_cert returns %d\n", certstatus);
	if (0 == certstatus)
	{
		printf("X509_STORE_CTX_get_error returns %d\n", X509_STORE_CTX_get_error(csc));
		X509_print_fp(stdout, X509_STORE_CTX_get_current_cert(csc));
	}




	// Many thanks to Richard Levitte for the following (. intiutive .) lines of code.
	if (OBJ_obj2nid(cert->cert_info->key->algor->algorithm) == NID_md5WithRSAEncryption)
	{
		printf("Re-setting algorithm type to RSA ($#¤?=## Microsoft!)\n");
		cert->cert_info->key->algor->algorithm = OBJ_nid2obj(NID_rsaEncryption);
	}

	//  X509_print_fp(stdout, cert);

	epk = X509_get_pubkey(cert);
	if (NULL == epk)
	{
		printf("Failed to extract public key from X509 structure\n");
	}

	if (EVP_PKEY_RSA == epk->type)
	{
		printf("Type is probably RSA\n");
		pubkey = (RSA *) epk->pkey.ptr;
	}


	cert_type = X509_certificate_type(cert, epk);

	printf("X509_certificate_type returned %d\n", cert_type);



	/* X509->cert_info->key->algor->algorithm is a ASN1_OBJECT   */

	return 0;

}
