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
 * Create an input text with the name "input_plain.txt". After that
 * run the program with ./foo. The decrypted text is stored in 
 * "output_dec.txt"
 *
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

int rsa_encrypt(FILE *in_file, FILE *out_file);
int rsa_decrypt(FILE *in_file, FILE *out_file);
EVP_PKEY *load_privkey(const char *file);
EVP_PKEY *load_pubkey(const char *file);

int main(int argc, char *argv[])
{
	FILE *in_file;
	FILE *out_enc_file;
	FILE *out_dec_file;
	int rv;

	/* Load input file and encrypt */
	in_file = fopen("input_plain.txt", "r");
	if (!in_file)
	{
		fprintf(stderr, "Error loading input file.\n");
		fprintf(stderr, "Create an input file with the name 'input_plain.txt'.\n");
		exit(2);
	}

	out_enc_file = fopen("output_enc.txt", "w+");
	if((rv = rsa_encrypt(in_file, out_enc_file)))
	{
		fprintf(stderr, "Error failed to encrypt: %d.\n", rv);
		return rv;
	}
	
	printf("File 'input_plain.txt' is encrypted and stored as 'output_enc.txt'.\n");

	fclose(out_enc_file);
	fclose(in_file);


	/* Load encrypted file and decrypt it */
	out_enc_file = fopen("output_enc.txt", "r");
	out_dec_file = fopen("output_dec.txt", "w");

	if((rv = rsa_decrypt(out_enc_file, out_dec_file)))
	{
		rv += 100; // 101 means Error with return value 1. Just 
		fprintf(stderr, "Error failed to decrypt: %d.\n", rv);
		return rv;
	}

	printf("File 'output_enc.txt' is decrypted and stored as 'output_dec.txt'.\n");
	fclose(out_enc_file);
	fclose(out_dec_file);

	printf("Success. Return value: %d\n", rv);
	return 0;
}



int rsa_encrypt(FILE *in_file, FILE *out_file)
{

	int retval = 0;
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_PKEY *pkey;
	unsigned char iv[EVP_MAX_IV_LENGTH];
	unsigned char *encrypted_key;
	unsigned char buffer[4096];
	unsigned char buffer_out[4096 + EVP_MAX_IV_LENGTH];
	size_t len;
	int len_out;
	int encrypted_key_length;
	uint32_t eklen_n;

	// Load pem file
	pkey = load_pubkey("public.pem");

	encrypted_key = malloc(EVP_PKEY_size(pkey));
	encrypted_key_length = EVP_PKEY_size(pkey);

	if (!EVP_SealInit(&ctx, EVP_des_ede_cbc(), &encrypted_key, &encrypted_key_length, iv, &pkey, 1))
	{
		fprintf(stderr, "EVP_SealInit: failed.\n");
		retval = 1;
		goto out_free;
	}

	/* First we write out the encrypted key length, then the encrypted key,
	 * then the iv (the IV length is fixed by the cipher we have chosen).
	 */
	eklen_n = htonl(encrypted_key_length);
	if (fwrite(&eklen_n, sizeof(eklen_n), 1, out_file) != 1)
	{
		retval = 2;
		goto out_free;
	}
	if (fwrite(encrypted_key, encrypted_key_length, 1, out_file) != 1)
	{
		retval = 3;
		goto out_free;
	}
	if (fwrite(iv, EVP_CIPHER_iv_length(EVP_des_ede_cbc()), 1, out_file) != 1)
	{
		retval = 4;
		goto out_free;
	}

	/* Now we process the input file and write the encrypted data to the
	 * output file. */

	while ((len = fread(buffer, 1, sizeof(buffer), in_file)) > 0)
	{
		if (!EVP_SealUpdate(&ctx, buffer_out, &len_out, buffer, len))
		{
			fprintf(stderr, "EVP_SealUpdate: failed.\n");
			retval = 5;
			goto out_free;
		}

		if (fwrite(buffer_out, len_out, 1, out_file) != 1)
		{
			perror("output file");
			retval = 6;
			goto out_free;
		}
	}

	if (!EVP_SealFinal(&ctx, buffer_out, &len_out))
	{
		fprintf(stderr, "EVP_SealFinal: failed.\n");
		retval = 8;
		goto out_free;
	}

	if (fwrite(buffer_out, len_out, 1, out_file) != 1)
	{
		perror("output file");
		retval = 9;
		goto out_free;
	}

out_free:
	EVP_PKEY_free(pkey);
	free(encrypted_key);

	EVP_CIPHER_CTX_cleanup(&ctx);
	return retval;

}

int rsa_decrypt(FILE *in_file, FILE *out_file)
{

	int retval = 0;
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);
	EVP_PKEY *pkey;
	unsigned char buffer[4096];
	unsigned char buffer_out[4096 + EVP_MAX_IV_LENGTH];
	size_t len;
	int len_out;
	unsigned char *encrypted_key;
	unsigned int encrypted_key_length;
	uint32_t eklen_n;
	unsigned char iv[EVP_MAX_IV_LENGTH];


	pkey = load_privkey("private.pem");

	encrypted_key = malloc(EVP_PKEY_size(pkey));

	/* First need to fetch the encrypted key length, encrypted key and IV */
	if (fread(&eklen_n, sizeof(eklen_n), 1, in_file) != 1)
	{
		retval = 1;
		goto out_free;
	}

	encrypted_key_length = ntohl(eklen_n);
	if (encrypted_key_length > EVP_PKEY_size(pkey))
	{
		fprintf(stderr, "Bad encrypted key length (%u > %d)\n", encrypted_key_length,
				EVP_PKEY_size(pkey));
		retval = 2;
		goto out_free;
	}
	if (fread(encrypted_key, encrypted_key_length, 1, in_file) != 1)
	{
		retval = 3;
		goto out_free;
	}
	if (fread(iv, EVP_CIPHER_iv_length(EVP_des_ede_cbc()), 1, in_file) != 1)
	{
		retval = 4;
		goto out_free;
	}

	if (!EVP_OpenInit(&ctx, EVP_des_ede_cbc(), encrypted_key, encrypted_key_length, iv, pkey))
	{
		fprintf(stderr, "EVP_OpenInit: failed.\n");
		retval = 5;
		goto out_free;
	}

	while ((len = fread(buffer, 1, sizeof(buffer), in_file)) > 0)
	{
		if (!EVP_OpenUpdate(&ctx, buffer_out, &len_out, buffer, len))
		{
			fprintf(stderr, "EVP_OpenUpdate: failed.\n");
			retval = 6;
			goto out_free;
		}

		if (fwrite(buffer_out, len_out, 1, out_file) != 1)
		{
			retval = 7;
			goto out_free;
		}
	}

	//TODO: Is buffer_out + len_out right? Look at it
	if (!EVP_OpenFinal(&ctx, buffer_out + len_out, &len_out))
	{
		fprintf(stderr, "EVP_OpenFinal: failed.\n");
		retval = 9;
		goto out_free;
	}

	if (fwrite(buffer_out, len_out, 1, out_file) != 1)
	{
		retval = 10;
		goto out_free;
	}

out_free:
	EVP_PKEY_free(pkey);
	free(encrypted_key);

	EVP_CIPHER_CTX_cleanup(&ctx);
	return retval;

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
