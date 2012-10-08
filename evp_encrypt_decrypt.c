#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>


int des3_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *ctx);
unsigned char *encrypt_example(EVP_CIPHER_CTX *ctx, unsigned char *plaintext, int *len);
unsigned char *decrypt_example(EVP_CIPHER_CTX *ctx, unsigned char *ciphertext, int *len);

int main(int argc, char *argv[])
{
	EVP_CIPHER_CTX ctx;

	unsigned char *ciphertext, *plaintext;
	unsigned char str[] = "123456789abcdef";
	unsigned char key_data[] = "KEYDATA_EXAMPLE";
	unsigned int salt[] = {12345, 54321};
	int olen, len, key_data_len;

	key_data_len = strlen((const char*)key_data);

	printf("Plaintext STR size %d byte\n", sizeof(str));
	printf("Plaintext STRlen size %d byte\n", strlen((const char*)str));

	/* gen key and iv. init the cipher ctx object */
	if (des3_init(key_data, key_data_len, (unsigned char *)&salt, &ctx)) 
	{
		printf("Couldn't initialize DES3 cipher\n");
		return -1;
	}

	/* We add 1 because we're encrypting a string which has a NULL Terminator
	 * and want the NULL terminator to be present when we decrypt */
	olen = len = strlen((const char*)str) + 1;

	/* The enc/dec functions deal with binary data and not C strings.
	 * strlen() will return length of the string without counting the '\0'
	 * string marker.  We always pass in the marker byte to the
	 * encrypt/decrypt functions so that after decryption we end up with a
	 * legal C string */
	ciphertext = encrypt_example(&ctx, str, &len);
	plaintext = decrypt_example(&ctx, ciphertext, &len);

	if (strncmp((const char *)plaintext, (const char *)str, olen)) 
		printf("FAIL: enc/dec failed for \"%s\"\n", str);
	else 
		printf("OK: enc/dec ok for \"%s\"\n", plaintext);

	free(ciphertext);
	free(plaintext);

	EVP_CIPHER_CTX_cleanup(&ctx);
	return 0;
}


/* Encrypt *len bytes of data All data going in & out is considered binary
   (unsigned char[]) */
unsigned char *encrypt_example(EVP_CIPHER_CTX *ctx, unsigned char *plaintext, int *len)
{

	/* max ciphertext len for a n bytes of plaintext is n +
	 * EVP_CIPHER_CTX_block_size -1 bytes */
	int c_len = *len + EVP_CIPHER_CTX_block_size(ctx) - 1;
	int f_len = 0;

	unsigned char *ciphertext = (unsigned char *)malloc(c_len);
 
	/* allows reusing of 'ctx' for multiple encryption cycles */
	EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, NULL);

	/* update ciphertext, c_len is filled with the length of ciphertext
	 * generated, len is the size of plaintext in bytes */
	EVP_EncryptUpdate(ctx, ciphertext, &c_len, plaintext, *len);

	/* update ciphertext with the final remaining bytes */
	EVP_EncryptFinal_ex(ctx, ciphertext + c_len, &f_len);

	*len = c_len + f_len;
	return ciphertext;
}

unsigned char *decrypt_example(EVP_CIPHER_CTX *ctx, unsigned char *ciphertext, int *len)
{

	/* plaintext will always be equal to or lesser than length of ciphertext */ 
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = (unsigned char *)malloc(p_len);

	EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, NULL);

	EVP_DecryptUpdate(ctx, plaintext, &p_len, ciphertext, *len);

	EVP_DecryptFinal_ex(ctx, plaintext + p_len, &f_len);
	printf("Encrypted: \"%s\"\n", plaintext);

	*len = p_len + f_len;
	return plaintext;
}
/* Create an 128 bit key and IV using the supplied key_data. Salt is added
 * for taste.  Fills in the encryption and decryption ctx objects and returns * 0 on success */
int des3_init(unsigned char *key_data, int key_data_len, unsigned char *salt, EVP_CIPHER_CTX *ctx)
{

	int i, nrounds = 5;
	unsigned char key[32], iv[32];

	/* EVP_des_ede3()		:three-key DES3 with ECB
	 * EVP_des_ede()		:two-key DES3 with ECB
	 * EVP_des_ede_cbc()	:two-key DES3 with CBC 
	 * EVP_des_ede3_cbc()	:three-key DES3 with CBC */

	/* Generate key & IV (initialization vector) for DES3 two-key CBC mode.
	 * SHA1 digest is used to hash the supplied key material. nrounds is the
	 * number of times the we hash the material. More rounds are more secure
	 * but slower. */
	i = EVP_BytesToKey(EVP_des_ede_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
	if (i != 16) 
	{
		printf("Key size is %d bits - should be 128 bits\n", i*8);
		return -1;
	}

	/* Print key and iv to be used */
	int cipher_key_len = EVP_CIPHER_key_length(EVP_des_ede_cbc());
	int cipher_iv_len = EVP_CIPHER_iv_length(EVP_des_ede_cbc());

	printf("Key and iv to be used:\n");
	printf("Key len\t: %d bit, %d byte\n", cipher_key_len * 8, cipher_key_len); 
	printf("Key\t: "); 
	for(i = 0; i < cipher_key_len; ++i) 
	{ 
		printf("%02x", key[i]); 
	} 
	printf("\n");

	printf("IV len\t: %d bit, %d byte\n", cipher_iv_len * 8, cipher_iv_len); 
	printf("IV\t: "); 
	for(i = 0; i < cipher_iv_len; ++i) 
	{ 
		printf("%02x", iv[i]); 
	} 
	printf("\n\n");

	// Initialize Cipher context, use same ctx for enc and dec
	EVP_CIPHER_CTX_init(ctx);
	EVP_EncryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, key, iv);
	EVP_DecryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, key, iv);

	return 0;
}
