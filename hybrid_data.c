/* We use OpenSSL's high-level implementation to implement an hybrid
 * crypto system. Hybrid cryptosystem is one which combines an asymetric
 * cryptosystem with a symetric crypto system. For more information look up: 
 *
 *		http://en.wikipedia.org/wiki/Hybrid_cryptosystem
 *
 * We use RSA for key encapsulation and DES for data encapsulation.
 *
 * Compile with: 
 * gcc -g -O0 -Wall foo.c -o foo -lssl -lcrypto 
 *
 * Just run the executable created below. Input data is "str" char array. 
 * Output is printed to the terminal
 * 
 * For more questions: ftharsln at gmail dot com
 */

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <arpa/inet.h> /* For htonl() */

#define BUFFER_SIZE 512

unsigned char *rsa_encrypt(unsigned char *plaintext, int *len);
unsigned char *rsa_decrypt(unsigned char *ciphertext, int *len);
EVP_PKEY *load_privkey(const char *file);
EVP_PKEY *load_pubkey(const char *file);

int main(int argc, char *argv[])
{
	unsigned char str[BUFFER_SIZE] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	unsigned char *ciphertext, *plaintext;
	int len, olen;

	/* We add 1 because we're encrypting a string which has a NULL Terminator
	 * and want the NULL terminator to be present when we decrypt */
	olen = len = strlen((const char*)str) + 1;

	printf("Plaintext length: %d\n", len);
	printf("String to be encrypted = {%s}\n\n", str);

	printf("Begin to encrypt...\n");
	ciphertext = rsa_encrypt(str, &len);

	printf("Begin to decrypt..\n");
	plaintext = rsa_decrypt(ciphertext, &olen);

	if (strncmp((const char *)plaintext, (const char *)str, olen)) 
		printf("\nFailed for the plaintext: {%s}\n", str);
	else 
		printf("\nOk, Decrypted string = {%s}\n", plaintext);

	free(ciphertext);
	free(plaintext);

	return 0;
}


unsigned char *rsa_encrypt(unsigned char *plaintext, int *len)
{

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_PKEY *pkey;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char *encrypted_key;
	int encrypted_key_length;
	uint32_t eklen_n;

	// Load pem file
	pkey = load_pubkey("public.pem");

	encrypted_key = malloc(EVP_PKEY_size(pkey));
	encrypted_key_length = EVP_PKEY_size(pkey);

	if (!EVP_SealInit(&ctx, EVP_des_ede_cbc(), &encrypted_key, &encrypted_key_length, iv, &pkey, 1))
	{
		fprintf(stderr, "EVP_SealInit: failed.\n");
		goto out_free;
	}

	eklen_n = htonl(encrypted_key_length);

	int size_header = sizeof(eklen_n) + encrypted_key_length +
					  EVP_CIPHER_iv_length(EVP_des_ede_cbc());

	/* max ciphertext len, see man EVP_CIPHER */
	int cipher_len = *len + EVP_CIPHER_CTX_block_size(&ctx) - 1;

	// header(contains iv, encreypted key and encreypted key length) + data
	unsigned char *ciphertext = (unsigned char *)malloc(size_header + cipher_len);

	/* First we write out the encrypted key length, then the encrypted key,
	 * then the iv (the IV length is fixed by the cipher we have chosen).
	 */
	int pos = 0;
	memcpy(ciphertext + pos, &eklen_n, sizeof(eklen_n));
	pos += sizeof(eklen_n);

	memcpy(ciphertext + pos, encrypted_key, encrypted_key_length);
	pos += encrypted_key_length;

	memcpy(ciphertext + pos, iv, EVP_CIPHER_iv_length(EVP_des_ede_cbc()));
	pos += EVP_CIPHER_iv_length(EVP_des_ede_cbc());

	/* Now we process the plaintext data and write the encrypted data to the
	 * ciphertext. cipher_len is filled with the length of ciphertext
	 * generated, len is the size of plaintext in bytes
	 * Also we have our updated position, we can skip the header via 
	 * ciphertext + pos */
	if (!EVP_SealUpdate(&ctx, ciphertext + pos, &cipher_len, plaintext, *len))
	{
		fprintf(stderr, "EVP_SealUpdate: failed.\n");
		goto out_free;
	}

	/* update ciphertext with the final remaining bytes */
	if (!EVP_SealFinal(&ctx, ciphertext + pos + cipher_len, &cipher_len))
	{
		fprintf(stderr, "EVP_SealFinal: failed.\n");
		goto out_free;
	}

out_free:
	EVP_PKEY_free(pkey);
	free(encrypted_key);

	EVP_CIPHER_CTX_cleanup(&ctx);
	return ciphertext;

}

unsigned char *rsa_decrypt(unsigned char *ciphertext, int *len)
{

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_PKEY *pkey;
	unsigned char *encrypted_key;
	unsigned int encrypted_key_length;
	uint32_t eklen_n;
	unsigned char iv[EVP_MAX_IV_LENGTH];


	pkey = load_privkey("private.pem");
	encrypted_key = malloc(EVP_PKEY_size(pkey));

	// plaintext will always be equal to or lesser than length of ciphertext 
	int plaintext_len = *len;

	// the length of ciphertest is at most plaintext + ciphers block size.
	int ciphertext_len = plaintext_len + EVP_CIPHER_block_size(EVP_des_ede_cbc());

	unsigned char *plaintext = (unsigned char *)malloc(ciphertext_len);

	/* First need to fetch the encrypted key length, encrypted key and IV */
	int pos = 0;
	memcpy(&eklen_n, ciphertext + pos, sizeof(eklen_n));
	pos += sizeof(eklen_n);

	encrypted_key_length = ntohl(eklen_n);

	memcpy(encrypted_key, ciphertext + pos, encrypted_key_length);
	pos += encrypted_key_length;

	memcpy(iv, ciphertext + pos, EVP_CIPHER_iv_length(EVP_des_ede_cbc()));
	pos += EVP_CIPHER_iv_length(EVP_des_ede_cbc());

	// Now we have our encrypted_key and the iv we can decrypt the reamining
	// data
	if (!EVP_OpenInit(&ctx, EVP_des_ede_cbc(), encrypted_key, encrypted_key_length, iv, pkey))
	{
		fprintf(stderr, "EVP_OpenInit: failed.\n");
		goto out_free;
	}

	if (!EVP_OpenUpdate(&ctx, plaintext, &plaintext_len, ciphertext + pos, ciphertext_len))
	{
		fprintf(stderr, "EVP_OpenUpdate: failed.\n");
		goto out_free;
	}

	int total_len = plaintext_len;

	if (!EVP_OpenFinal(&ctx, plaintext + total_len, &plaintext_len))
	{
		fprintf(stderr, "EVP_OpenFinal warning: failed.\n");
	}


out_free:
	EVP_PKEY_free(pkey);
	free(encrypted_key);

	EVP_CIPHER_CTX_cleanup(&ctx);

	*len = plaintext_len + total_len;
	return  plaintext;

}


EVP_PKEY *load_privkey(const char *file)
{

	RSA *rsa_pkey = NULL;
	BIO *rsa_pkey_file = NULL;
	EVP_PKEY *pkey = EVP_PKEY_new();

	// Create a new BIO file structure to be used with PEM file
	rsa_pkey_file = BIO_new(BIO_s_file());
	if (rsa_pkey_file == NULL)
	{
		fprintf(stderr, "Error crating a new BIO file.\n");
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	// Read PEM file using BIO's file structure
	if (BIO_read_filename(rsa_pkey_file, file) <= 0)
	{
		fprintf(stderr, "Error opening %s\n",file);
		ERR_print_errors_fp(stderr);
		goto end;
	}

	// Read RSA based PEM file into rsa_pkey structure
	if (!PEM_read_bio_RSAPrivateKey(rsa_pkey_file, &rsa_pkey, NULL, NULL))
	{
		fprintf(stderr, "Error loading RSA Private Key File.\n");
		ERR_print_errors_fp(stderr);
		goto end;
	}

	// Populate pkey with the rsa key. rsa_pkey is owned by pkey,
	// therefore if we free pkey, rsa_pkey will be freed  too
    if (!EVP_PKEY_assign_RSA(pkey, rsa_pkey))
    {
        fprintf(stderr, "Error assigning EVP_PKEY_assign_RSA: failed.\n");
        goto end;
    }

end:
	if (rsa_pkey_file != NULL)
		BIO_free(rsa_pkey_file);
	if (pkey == NULL)
	{
		fprintf(stderr, "Error unable to load %s\n", file);
		ERR_print_errors_fp(stderr);
	}
	return(pkey);
}

EVP_PKEY *load_pubkey(const char *file)
{

	RSA *rsa_pkey = NULL;
	BIO *rsa_pkey_file = NULL;
	EVP_PKEY *pkey = EVP_PKEY_new();

	// Create a new BIO file structure to be used with PEM file
	rsa_pkey_file = BIO_new(BIO_s_file());
	if (rsa_pkey_file == NULL)
	{
		fprintf(stderr, "Error crating a new BIO file.\n");
		ERR_print_errors_fp(stderr);
		goto end;
	}
	
	// Read PEM file using BIO's file structure
	if (BIO_read_filename(rsa_pkey_file, file) <= 0)
	{
		fprintf(stderr, "Error opening %s\n",file);
		ERR_print_errors_fp(stderr);
		goto end;
	}

	// Read RSA based PEM file into rsa_pkey structure
	if (!PEM_read_bio_RSA_PUBKEY(rsa_pkey_file, &rsa_pkey, NULL, NULL))
	{
		fprintf(stderr, "Error loading RSA Public Key File.\n");
		ERR_print_errors_fp(stderr);
		goto end;
	}

	// Populate pkey with the rsa key. rsa_pkey is owned by pkey,
	// therefore if we free pkey, rsa_pkey will be freed  too
    if (!EVP_PKEY_assign_RSA(pkey, rsa_pkey))
    {
        fprintf(stderr, "Error assigning EVP_PKEY_assign_RSA: failed.\n");
        goto end;
    }

end:
	if (rsa_pkey_file != NULL)
		BIO_free(rsa_pkey_file);
	if (pkey == NULL)
	{
		fprintf(stderr, "Error unable to load %s\n", file);
		ERR_print_errors_fp(stderr);
	}
	return(pkey);
}
