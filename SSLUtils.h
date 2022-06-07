#pragma once
#include <stdio.h>
#include <winsock2.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl\tls1.h>
#include <openssl/x509v3.h>
#include <openssl/applink.c>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

#define KEY_FILE "server.key"
#define CERT_FILE "server.crt"

#define REQ_DN_C "YC"
#define REQ_DN_ST "YC"
#define REQ_DN_L "YC"
#define REQ_DN_O "YC"
#define REQ_DN_OU "YC"
#define REQ_DN_CN "YC"

X509* g_ca_crt = NULL;
EVP_PKEY* g_ca_key = NULL;
#define RSA_KEY_BITS (1024)

typedef struct _TRANSFER
{
	BOOL inbound;
	SSL* client_ssl;
	SSL* server_ssl;
}TRANSFER, * PTRANSFER;

typedef struct _CONNDATA
{
	SOCKET t;
	SSL* client_ssl;
	HANDLE hEvent;
}CONNDATA,*PCONNDATA;

void SSL_Error(char* custom_string) {
	char error_buffer[256] = { 0 };

	printf("%s, ", custom_string);
	ERR_error_string(ERR_get_error(), error_buffer);
	printf("%s\n", error_buffer);
}

SSL* Server_SSL_Init(PVOID callback,PVOID args) {
	// 加载SSL环境
	SSL_CTX* server_ctx = SSL_CTX_new(SSLv23_server_method());
	if (NULL == server_ctx)
	{
		SSL_Error("Init ssl ctx error");
		return NULL;
	}

	//设置回调函数
	SSL_CTX_set_tlsext_servername_callback(server_ctx, callback);
	//这里在设置回调的参数
	SSL_CTX_set_tlsext_servername_arg(server_ctx, args);

	// 设置证书文件的口令
	//SSL_CTX_set_default_passwd_cb_userdata(server_ctx, "木有密碼");

	// 加载证书
	if (SSL_CTX_use_certificate_file(server_ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0)
	{
		SSL_Error("Load cert file error");
		return NULL;
	}

	// 加载私钥
	if (SSL_CTX_use_PrivateKey_file(server_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0)
	{
		SSL_Error("Load cert file error");
		return NULL;
	}

	// 检查私钥和证书是否匹配
	if (!SSL_CTX_check_private_key(server_ctx))
	{
		printf("Private key does not match the certificate public key\n");
		return NULL;
	}

	SSL* ssl = SSL_new(server_ctx);
	if (NULL == ssl)
	{
		SSL_Error("Create ssl error");
		return NULL;
	}

	return ssl;
}

SSL* Client_SSL_Init() {
	SSL_CTX* client_ctx;

	client_ctx = SSL_CTX_new(SSLv23_client_method());

	if (NULL == client_ctx) {
		SSL_Error((char*)"Init ssl ctx error");
		return NULL;
	}

	SSL* ssl = SSL_new(client_ctx);
	if (NULL == ssl) {
		SSL_Error((char*)"Create ssl error");
		return NULL;
	}

	return ssl;
}

//===============================================https://github.com/zozs/openssl-sign-by-ca
//生成x509证书的代码
int generate_signed_key_pair(EVP_PKEY* ca_key, X509* ca_crt, EVP_PKEY** key, X509** crt, X509* server_x509)
{
	/* Generate the private key and corresponding CSR. */
	X509_REQ* req = NULL;
	if (!generate_key_csr(key, &req)) {
		printf("Failed to generate key and/or CSR!\n");
		return 0;
	}

	/* Sign with the CA. */
	*crt = X509_new();
	if (!*crt) goto err;

	X509_set_version(*crt, 2); /* Set version to X509v3 */

	/* Generate random 20 byte serial. */
	if (!generate_set_random_serial(*crt)) goto err;

	/* Set issuer to CA's subject. */
	X509_set_issuer_name(*crt, X509_get_subject_name(ca_crt));

	/* Set validity of certificate to 2 years. */
	X509_gmtime_adj(X509_get_notBefore(*crt), 0);
	X509_gmtime_adj(X509_get_notAfter(*crt), (long)2 * 365 * 24 * 3600);

	/* Get the request's subject and just use it (we don't bother checking it since we generated
	 * it ourself). Also take the request's public key. */
	X509_set_subject_name(*crt, X509_REQ_get_subject_name(req));
	EVP_PKEY* req_pubkey = X509_REQ_get_pubkey(req);
	X509_set_pubkey(*crt, req_pubkey);
	EVP_PKEY_free(req_pubkey);


	/*GENERAL_NAMES* gens = sk_GENERAL_NAME_new_null();
	GENERAL_NAME* gen = GENERAL_NAME_new();
	ASN1_IA5STRING* ia5 = ASN1_IA5STRING_new();
	ASN1_STRING_set(ia5, "www.baidu.com", strlen("www.baidu.com"));
	GENERAL_NAME_set0_value(gen, GEN_DNS, ia5);
	sk_GENERAL_NAME_push(gens, gen);
	X509_add1_ext_i2d(*crt, NID_subject_alt_name, gens, 0, X509V3_ADD_DEFAULT);
	GENERAL_NAMES_free(gens);*/

	
	//这里更新dnsName，在签名之前 https://github.com/openssl/openssl/issues/11706  
	GENERAL_NAMES* altNames = (GENERAL_NAMES*)X509_get_ext_d2i(server_x509, NID_subject_alt_name, NULL, NULL);
	if (altNames)
	{
		GENERAL_NAMES* gens = sk_GENERAL_NAME_new_null();
		
		for (int i = 0; i < sk_GENERAL_NAME_num(altNames); i++)
		{
			char tmp[0x100] = { 0 };
			GENERAL_NAME* altName = sk_GENERAL_NAME_value(altNames, i);
			
			GENERAL_NAME* gen = GENERAL_NAME_new();
			ASN1_IA5STRING* ia5 = ASN1_IA5STRING_new();
			ASN1_STRING_set(ia5, ASN1_STRING_data(GENERAL_NAME_get0_value(altName, NULL)), strlen(ASN1_STRING_data(GENERAL_NAME_get0_value(altName, NULL))));
			GENERAL_NAME_set0_value(gen, GEN_DNS, ia5);
			sk_GENERAL_NAME_push(gens, gen);
			//ASN1_IA5STRING_free(ia5);
			//GENERAL_NAME_free(gen);
		}
		X509_add1_ext_i2d(*crt, NID_subject_alt_name, gens, 0, X509V3_ADD_DEFAULT);
		GENERAL_NAMES_free(gens);
	}

	/* Now perform the actual signing with the CA. */
	if (X509_sign(*crt, ca_key, EVP_sha256()) == 0) goto err;

	X509_REQ_free(req);
	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(req);
	X509_free(*crt);
	return 0;
}

int generate_key_csr(EVP_PKEY** key, X509_REQ** req)
{
	*key = NULL;
	*req = NULL;
	RSA* rsa = NULL;
	BIGNUM* e = NULL;

	*key = EVP_PKEY_new();
	if (!*key) goto err;
	*req = X509_REQ_new();
	if (!*req) goto err;
	rsa = RSA_new();
	if (!rsa) goto err;
	e = BN_new();
	if (!e) goto err;

	BN_set_word(e, 65537);
	if (!RSA_generate_key_ex(rsa, RSA_KEY_BITS, e, NULL)) goto err;
	if (!EVP_PKEY_assign_RSA(*key, rsa)) goto err;

	X509_REQ_set_pubkey(*req, *key);

	/* Set the DN of the request. */
	X509_NAME* name = X509_REQ_get_subject_name(*req);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)REQ_DN_C, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (const unsigned char*)REQ_DN_ST, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (const unsigned char*)REQ_DN_L, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)REQ_DN_O, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (const unsigned char*)REQ_DN_OU, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)REQ_DN_CN, -1, -1, 0);

	/* Self-sign the request to prove that we posses the key. */
	if (!X509_REQ_sign(*req, *key, EVP_sha256())) goto err;

	BN_free(e);

	return 1;
err:
	EVP_PKEY_free(*key);
	X509_REQ_free(*req);
	RSA_free(rsa);
	BN_free(e);
	return 0;
}

int generate_set_random_serial(X509* crt)
{
	/* Generates a 20 byte random serial number and sets in certificate. */
	unsigned char serial_bytes[20];
	if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) return 0;
	serial_bytes[0] &= 0x7f; /* Ensure positive serial! */
	BIGNUM* bn = BN_new();
	BN_bin2bn(serial_bytes, sizeof(serial_bytes), bn);
	ASN1_INTEGER* serial = ASN1_INTEGER_new();
	BN_to_ASN1_INTEGER(bn, serial);

	X509_set_serialNumber(crt, serial); // Set serial.

	ASN1_INTEGER_free(serial);
	BN_free(bn);
	return 1;
}

int load_ca(const char* ca_key_path, EVP_PKEY** ca_key, const char* ca_crt_path, X509** ca_crt)
{
	BIO* bio = NULL;
	*ca_crt = NULL;
	*ca_key = NULL;

	/* Load CA public key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_crt_path)) goto err;
	*ca_crt = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!*ca_crt) goto err;
	BIO_free_all(bio);

	/* Load CA private key. */
	bio = BIO_new(BIO_s_file());
	if (!BIO_read_filename(bio, ca_key_path)) goto err;
	*ca_key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if (!ca_key) goto err;
	BIO_free_all(bio);
	return 1;
err:
	BIO_free_all(bio);
	X509_free(*ca_crt);
	EVP_PKEY_free(*ca_key);
	return 0;
}

X509* UpdateX509(X509* server_x509, EVP_PKEY** pKey)
{
	/* Generate keypair and then print it byte-by-byte for demo purposes. */
	X509* crt = NULL;
	EVP_PKEY* key = NULL;
	
	int ret = generate_signed_key_pair(g_ca_key, g_ca_crt, &key, &crt,server_x509);
	if (!ret) 
	{
		printf("Failed to generate key pair!\n");
		return NULL;
	}
	*pKey = key;
	return crt;
}

SSL_CTX* GetSSLCTX(X509* cert, EVP_PKEY* key)
{
	SSL_CTX* ctx = NULL;

	ctx = SSL_CTX_new(SSLv23_server_method());
	if (ctx == NULL)
		SSL_Error("Fail to init ssl ctx!");
	if (cert && key)
	{
		if (SSL_CTX_use_certificate(ctx, cert) != 1)
			SSL_Error("Certificate error");
		if (SSL_CTX_use_PrivateKey(ctx, key) != 1)
			SSL_Error("key error");
		if (SSL_CTX_check_private_key(ctx) != 1)
			SSL_Error("Private key does not match the certificate public key");
	}

	return ctx;
}

void initCa()
{
	char* ca_key_path = "ca.key";
	char* ca_crt_path = "ca.crt";
	if (!load_ca(ca_key_path, &g_ca_key, ca_crt_path, &g_ca_crt))
	{
		printf("Failed to load CA certificate and/or key!\n");
	}
}
//===============================================


