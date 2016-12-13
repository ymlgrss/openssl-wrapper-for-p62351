#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509_vfy.h>

#include "p62351.h"

struct p62351_tls_ctx_s
{
	SSL_CTX * ctx;
	X509_STORE * store;
	int renegotiate_bytes;
	int renegotiate_timeout;
};

struct p62351_tls_s
{
	SSL *ssl;
	int is_nonblocking;
};

/*---------------??֤????Ѽ????-----------------------*/

static X509 *lookup_cert_match(X509_STORE_CTX *ctx, X509 *x)
{
	STACK_OF(X509) *certs;
	X509 *xtmp = NULL;
	int i;
	/* Lookup all certs with matching subject name */
	certs = ctx->lookup_certs(ctx, X509_get_subject_name(x));
	if (certs == NULL)
		return NULL;
	/* Look for exact match */
	for (i = 0; i < sk_X509_num(certs); i++) {
		xtmp = sk_X509_value(certs, i);
		if (!X509_cmp(xtmp, x))
			break;
	}
	if (i < sk_X509_num(certs))
		CRYPTO_add(&xtmp->references, 1, CRYPTO_LOCK_X509);
	else
		xtmp = NULL;
	sk_X509_pop_free(certs, X509_free);
	return xtmp;
}

/*----------------????֤??֤?ص????-------------------------*/

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	if (preverify_ok)
	{
		if (lookup_cert_match(ctx, ctx->cert))
		{
			printf("matched!\n");
			preverify_ok = 1;
		}
		else
		{
			printf("not matched!\n");
			preverify_ok = 0;
		}
	}
	return preverify_ok;
}

p62351_tls_ctx_t *p62351_tls_ctx_new(const p62351_tls_ctx_config_t *config)
{
	p62351_tls_ctx_t *tls_ctx;
	SSL_CTX *ctx;
	FILE *fp;
	EVP_PKEY *pkey;
	X509 *cert;
	STACK_OF(X509) *ca = NULL;
	PKCS12 *p12;
	BIO *crl_file;
	X509_CRL *crl;
	X509_VERIFY_PARAM *param;
	int  seed_int[100]; /*????????*/

	/* -------------??ʼ??openssl-------------------------------- */

	SSL_library_init();
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	/* -----------??????????ɻ??, WIN32ƽ̨???----------------*/

	srand((unsigned)time(NULL));
	int i;
	for (i= 0; i < 100; i++)
		seed_int[i] = rand();
	RAND_seed(seed_int, sizeof(seed_int));

	/*------------------????CTX???------------------------------*/

	ctx = SSL_CTX_new(TLSv1_method());
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	SSL_CTX_load_verify_locations(ctx, config->ca_file, NULL);

	if (!(fp = fopen(config->cert_file, "rb")))
	{
		fprintf(stderr, "Error opening file %s\n", config->cert_file);
		exit(1);
	}
	p12 = d2i_PKCS12_fp(fp, NULL);
	fclose(fp);
	if (!p12)
	{
		fprintf(stderr, "Error reading PKCS#12 file\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	if (!PKCS12_parse(p12, config->cert_password, &pkey, &cert, &ca))
	{
		fprintf(stderr, "Error parsing PKCS#12 file\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (SSL_CTX_use_certificate(ctx, cert) <= 0)
	{
		fprintf(stderr, "Error using certificate\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0)
	{
		fprintf(stderr, "Error using private key\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}
	/*
	if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
	ERR_print_errors_fp(stderr);
	getchar();
	exit(-1);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
	ERR_print_errors_fp(stderr);
	getchar();
	exit(-1);
	}*/

	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the certificate public key\n");
		ERR_print_errors_fp(stderr);
		exit(1);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	SSL_CTX_set_cipher_list(ctx, "ALL:!NULL");

	SSL_CTX_set_timeout(ctx, config->handshake_timeout);

	tls_ctx = (p62351_tls_ctx_t *)malloc(sizeof(p62351_tls_ctx_t));
	tls_ctx->ctx = ctx;
	tls_ctx->store = SSL_CTX_get_cert_store(ctx);
	tls_ctx->renegotiate_bytes = config->renegotiate_bytes;
	tls_ctx->renegotiate_timeout = config->renegotiate_timeout;

	if (config->crl_file)
	{
		crl_file = BIO_new_file(config->crl_file, "r");
		if (!crl_file)
		{
			fprintf(stderr, "Error creating BIO for crl file\n");
			ERR_print_errors_fp(stderr);
			exit(1);
		}
		crl = PEM_read_bio_X509_CRL(crl_file, NULL, NULL, NULL);
		X509_STORE_add_crl(tls_ctx->store, crl);

		/* Enable CRL checking */
		param = X509_VERIFY_PARAM_new();
		X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_CRL_CHECK);
		X509_STORE_set1_param(tls_ctx->store, param);
		X509_VERIFY_PARAM_free(param);
	}

	return tls_ctx;
}

int p62351_tls_add_peer_cert(p62351_tls_ctx_t *ctx, const char *certpath)
{
	BIO * b;
	X509 *cert;

	b = BIO_new_file(certpath, "r");
	if (!b)
	{
		fprintf(stderr, "Error creating BIO for peer certificate\n");
		ERR_print_errors_fp(stderr);
		return 1;
	}
	cert = PEM_read_bio_X509(b, NULL, NULL, NULL);
	if (!cert)
	{
		fprintf(stderr, "Error loading peer certificate\n");
		ERR_print_errors_fp(stderr);
		return 1;
	}
	X509_STORE_add_cert(ctx->store, cert);
	SSL_CTX_set_verify(ctx->ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 
						verify_callback);
	BIO_free(b);
	return 0;
}

p62351_tls_t *p62351_tls_new(p62351_tls_ctx_t *ctx, int sock, int is_client, int is_nonblocking)
{
	SSL *ssl;
	BIO *sbio;
	p62351_tls_t *tls;
	int ret;

	sbio = BIO_new_socket(sock, BIO_NOCLOSE);		
	if (sbio == NULL)
	{
		perror("Error BIO_new_socket()");
		exit(1);
	}
	BIO_set_ssl_renegotiate_bytes(sbio, ctx->renegotiate_bytes);
	BIO_set_ssl_renegotiate_timeout(sbio, ctx->renegotiate_timeout);
	ssl = SSL_new(ctx->ctx);									
	if (ssl == NULL)
	{
		perror("Error SSL_new()");
		exit(1);
	}
	SSL_set_bio(ssl, sbio, sbio);

	if (is_nonblocking)
	{
		if (is_client)
		{
			SSL_set_connect_state(ssl);
		}
		else
		{
			SSL_set_accept_state(ssl);
		}
	}
	else
	{
		if (is_client)
		{
			ret = SSL_connect(ssl);
		}
		else
		{
			ret = SSL_accept(ssl);
		}
		if (ret <= 0)
			return NULL;
	}

	tls = (p62351_tls_t *)malloc(sizeof(p62351_tls_ctx_t));
	tls->is_nonblocking = is_nonblocking;
	tls->ssl = ssl;

	return tls;
}

int p62351_tls_read(p62351_tls_t *tls, char *buf, int len, int *err)
{
	int ret;
	ret = SSL_read(tls->ssl, buf, len - 1);
	switch (SSL_get_error(tls->ssl, ret))
	{
	case SSL_ERROR_NONE:
		*err = 0;
		break;
	case SSL_ERROR_ZERO_RETURN:
		printf("DONE\n");
		*err = 1;
		break;
	case SSL_ERROR_WANT_READ:
		printf("WANT_READ BLOCK\n");
		*err = 2;
		break;
	case SSL_ERROR_WANT_WRITE:
		printf("WANT_WRITE BLOCK\n");
		*err = 3;
		break;
	case SSL_ERROR_SYSCALL:
	case SSL_ERROR_SSL:
		printf("ERROR\n");
		*err = 4;
	default:
		printf("ERROR\n");
		*err = 4;
	}
	return ret;
}

int p62351_tls_write(p62351_tls_t *tls, const char *buf, int len, int *err)
{
	int ret;
	ret = SSL_write(tls->ssl, buf, len);
	switch (SSL_get_error(tls->ssl, ret))
	{
	case SSL_ERROR_NONE:
		*err = 0;
		break;
	case SSL_ERROR_ZERO_RETURN:
		printf("DONE\n");
		*err = 1;
		break;
	case SSL_ERROR_WANT_READ:
		printf("BLOCK\n");
		*err = 2;
		break;
	case SSL_ERROR_WANT_WRITE:
		printf("BLOCK\n");
		*err = 3;
		break;
	case SSL_ERROR_SYSCALL:
	case SSL_ERROR_SSL:
		printf("ERROR\n");
		*err = 4;
	default:
		printf("ERROR\n");
		*err = 4;
	}
	return ret;
}

void p62351_tls_free(p62351_tls_t *tls)
{
	SSL_shutdown(tls->ssl);
	SSL_free(tls->ssl);
	free(tls);
}

void p62351_tls_ctx_free(p62351_tls_ctx_t *ctx)
{
	SSL_CTX_free(ctx->ctx);
	X509_STORE_free(ctx->store);
	free(ctx);
}

const char *p62351_get_last_error_string(void)
{
	char buf[128];
	unsigned long error;

	error = ERR_get_error();
	if (error != 0)
	{
		return ERR_error_string(error, buf);
	}
	else
	{
		printf("No error!");
		return NULL;
	}
}

const char *p62351_tls_get_cipher_name(p62351_tls_t *tls)
{
	return SSL_get_cipher(tls->ssl);
}

const char *p62351_tls_get_peer_cert_subject(p62351_tls_t *tls)
{
	X509 *client_cert;
	char *str;

	client_cert = SSL_get_peer_certificate(tls->ssl);
	if (client_cert != NULL)
	{

		str = X509_NAME_oneline(X509_get_subject_name(client_cert), 0, 0);
		X509_free(client_cert);
		if (str == NULL)
		{
			fprintf(stderr, "No subject name\n");
		}
		return str;
	}
	else
	{
		printf("Peer does not have certificate\n");
		return NULL;
	}
}

const char *p62351_tls_get_peer_cert_issuer(p62351_tls_t *tls)
{
	X509 *client_cert;
	char *str;

	client_cert = SSL_get_peer_certificate(tls->ssl);
	if (client_cert != NULL)
	{
		str = X509_NAME_oneline(X509_get_issuer_name(client_cert), 0, 0);
		X509_free(client_cert);
		if (str == NULL)
		{
			fprintf(stderr, "No issuer name\n");
		}
		return str;
	}
	else
	{
		printf("Client does not have certificate\n");
		return NULL;
	}
}
