#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "enet/ssl/ecdh.h"
#include "openssl/hmac.h"
#include "openssl/ec.h"
#include "openssl/obj_mac.h"
#include "enet/ssl/common.h"

int encrypt_message(unsigned int peerIndex, const unsigned char* buffer,
	unsigned int inSize, unsigned char* bufferOut, unsigned int outBufferSize,
	const unsigned char *key, const unsigned char *iv)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	const EVP_CIPHER *cipherMethod = EVP_aes_256_cbc();
	int length = 0;
	int totallength = 0;

	if (EVP_EncryptInit_ex(ctx, cipherMethod, NULL, (unsigned char*)key, (unsigned char*)iv) != 1)
	{
		return -1;
	}

	if (EVP_EncryptUpdate(ctx, bufferOut, &length, buffer, inSize) != 1)
	{
		return -1;
	}

	totallength = length;

	if (EVP_EncryptFinal_ex(ctx, bufferOut + length, &length) != 1)
	{
		return -1;
	}
	totallength += length;

	EVP_CIPHER_CTX_cleanup(ctx);
	return totallength;
}

int calculate_hmac(unsigned int peerIndex, const unsigned char* message, unsigned int msgLength, unsigned char* hmacBuffer, unsigned int* hmacLength,
	const unsigned char *key, uint8_t key_len)
{
	// Use SHA256
	HMAC(EVP_sha256(), key, key_len, message, msgLength, hmacBuffer, hmacLength);
	if (hmacLength > 0)
	{
		return 1;
	}

	return -1;
}

int decrypt_message(unsigned int peerIndex, const unsigned char* buffer,
	unsigned int inSize, unsigned char* bufferOut, unsigned int outBufferSize,
	const unsigned char *key, const unsigned char *iv)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	const EVP_CIPHER *cipherMethod = EVP_aes_256_cbc();
	int length = 0;
	int totallength = 0;

	if (EVP_DecryptInit_ex(ctx, cipherMethod, NULL, key, iv) != 1)
	{
		return -1;
	}

	if (EVP_DecryptUpdate(ctx, bufferOut, &length, buffer, inSize) != 1)
	{
		return -1;
	}
	totallength = length;

	if (EVP_DecryptFinal_ex(ctx, bufferOut + length, &length) != 1)
	{
		return -1;
	}
	totallength += length;

	EVP_CIPHER_CTX_cleanup(ctx);
	return totallength;
}

bool rand_salt(uint8_t salt[], int32_t bytes)
{
	return (RAND_bytes(salt, bytes) == 1);
}

bool generate_ecdh_keys(uint8_t ecdh_public_key[CRYPTO_EC_PUB_KEY_LEN],
	uint8_t ecdh_private_key[CRYPTO_EC_PRIV_KEY_LEN], const char* file_prefix)
{
	int len = 0;
	bool ret = false;

	EC_KEY *ecdh = EC_KEY_new();
	const EC_POINT *point = NULL;
	const EC_GROUP *group = NULL;

	//Generate Public
	ecdh = EC_KEY_new_by_curve_name(CRYPTO_CURVE_NID);

	group = EC_KEY_get0_group(ecdh);

	/* get x y */
	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
	{
		if (!EC_KEY_generate_key(ecdh))
		{
			printf("Ecdh NIST P-256 generate error.");
			goto err;
		}

		//char file_name[128] = { 0, };
		//strcpy_s(file_name, sizeof(file_name), file_prefix);
		//strcat_s(file_name, sizeof(file_name), "-public-key.pem");
		//FILE* fp = fopen(file_name, "r");

		//if(fp == nullptr)
		//{
		//	printf("File open does not exist.");
		//	fp = fopen(file_name, "w");

		//	PEM_write_EC_PUBKEY(fp, ecdh);
		//	fclose(fp);
		//}
		//else
		//{
		//	PEM_read_EC_PUBKEY(fp, &ecdh, NULL, NULL);
		//	fclose(fp);
		//}
		//
		//memset(file_name, 0, sizeof(file_name));
		//strcpy_s(file_name, sizeof(file_name), file_prefix);
		//strcat_s(file_name, sizeof(file_name), "-private-key.pem");
		//fp = fopen(file_name, "r");
		//if(fp == nullptr)
		//{
		//	printf("File open does not exist.");

		//	fp = fopen(file_name, "w");
		//	PEM_write_ECPrivateKey(fp, ecdh, NULL, NULL, 0, NULL, NULL);
		//	fclose(fp);
		//}
		//else
		//{
		//	PEM_read_ECPrivateKey(fp, &ecdh, NULL, NULL);
		//	fclose(fp);
		//}


		point = EC_KEY_get0_public_key(ecdh);

		len = EC_POINT_point2oct(group,
			point,
			POINT_CONVERSION_UNCOMPRESSED,
			ecdh_public_key,
			CRYPTO_EC_PUB_KEY_LEN, NULL);
		if (len != CRYPTO_EC_PUB_KEY_LEN)
		{
			printf("Ecdh NIST P-256 public key get error.");
			goto err;
		}

		len = BN_bn2bin(EC_KEY_get0_private_key(ecdh), ecdh_private_key);
		if (len != CRYPTO_EC_PRIV_KEY_LEN)
		{
			printf("Ecdh NIST P-256 private key get error.");
			goto err;
		}

		ret = true;
	}

err:
	EC_KEY_free(ecdh);
	return ret;
}

bool calc_ecdh_shared_key(const uint8_t ecdh1_public_key[CRYPTO_EC_PUB_KEY_LEN],
	const uint8_t ecdh1_private_key[CRYPTO_EC_PRIV_KEY_LEN],
	const uint8_t ecdh2_public_key[CRYPTO_EC_PUB_KEY_LEN],
	uint8_t ecdh_shared_key[CRYPTO_ECDH_SHARED_KEY_LEN])
{
	int len = 0;
	int ret = false;
	EC_KEY *ecdh = EC_KEY_new();
	const EC_GROUP *group = NULL;
	BIGNUM   *priv = NULL;
	EC_POINT *p_ecdh1_public = NULL;
	EC_POINT *p_ecdh2_public = NULL;

	ecdh = EC_KEY_new_by_curve_name(CRYPTO_CURVE_NID);
	if (ecdh == NULL)
	{
		printf("Ecdh key by curve name error.");
		goto err;
	}

	group = EC_KEY_get0_group(ecdh);

	if (EC_METHOD_get_field_type(EC_GROUP_method_of(group)) == NID_X9_62_prime_field)
	{
		/* 1==> Set ecdh1's public and privat key. */
		p_ecdh1_public = EC_POINT_new(group);
		if (p_ecdh1_public == NULL)
		{
			printf("EC_POINT new error.");
			goto err;
		}

		ret = EC_POINT_oct2point(group,
			p_ecdh1_public,
			ecdh1_public_key,
			CRYPTO_EC_PUB_KEY_LEN, NULL);
		if (!ret)
		{
			printf("EC_POINT oct2point error.");
			goto err;
		}

		if (!EC_KEY_set_public_key(ecdh, p_ecdh1_public))
		{
			printf("Ecdh set public key error.");
		}

		priv = BN_bin2bn(ecdh1_private_key,
			CRYPTO_EC_PRIV_KEY_LEN,
			NULL);
		if (!EC_KEY_set_private_key(ecdh, priv))
		{
			printf("set private error \n");
		}
		/*-------------*/

		/* 2==> Set ecdh2's public key */
		p_ecdh2_public = EC_POINT_new(group);
		if (p_ecdh2_public == NULL)
		{
			printf("EC_POINT new error.");
			goto err;
		}

		ret = EC_POINT_oct2point(group,
			p_ecdh2_public,
			ecdh2_public_key,
			CRYPTO_EC_PUB_KEY_LEN,
			NULL);
		if (!ret)
		{
			printf("EC_POINT oct2point error.");
			goto err;
		}

		if (!EC_KEY_set_public_key(ecdh, p_ecdh2_public))
		{
			printf("Ecdh set public key error.");
			goto err;
		}
		/*------------*/

		/* 3==> Calculate the shared key of ecdh1 and ecdh2 */
		len = ECDH_compute_key(ecdh_shared_key,
			CRYPTO_ECDH_SHARED_KEY_LEN,
			p_ecdh2_public,
			ecdh,
			NULL);
		if (len != CRYPTO_ECDH_SHARED_KEY_LEN)
		{
			printf("Ecdh compute key error.");
			goto err;
		}

		ret = 0;
	}

err:
	if (priv)
		BN_free(priv);
	if (ecdh)
		EC_KEY_free(ecdh);
	if (p_ecdh1_public)
		EC_POINT_free(p_ecdh1_public);
	if (p_ecdh2_public)
		EC_POINT_free(p_ecdh2_public);

	return (ret == 0);
}

bool hmac_sha256(uint8_t hmac[CRYPTO_HMAC_SHA256],
	const uint8_t key[], uint8_t key_len,
	const uint8_t data[], uint8_t data_len)
{
	unsigned int resultlen = 0;
	HMAC(EVP_sha256(), key, key_len, data, data_len, hmac, &resultlen);

	if (resultlen != CRYPTO_HMAC_SHA256)
	{
		printf("HMAC SHA-256 error.");
		return false;
	}

	return true;
}

bool bytes_xor(const uint8_t data1[], int data1_len,
	const uint8_t data2[], int data2_len,
	uint8_t out[])
{
	int i = 0;

	if ((data1_len != data2_len) || (out == NULL))
		return false;

	for (i = 0; i < data1_len; i++)
	{
		out[i] = data1[i] ^ data2[i];
	}

	return true;
}

bool generate_hkdf_bytes(const uint8_t ecdh_shared_key[CRYPTO_ECDH_SHARED_KEY_LEN],
	const uint8_t salt[CRYPTO_SALT_LEN],
	const uint8_t info[], int info_len,
	uint8_t out[])
{
	const EVP_MD *md = EVP_sha256();
	unsigned char prk[CRYPTO_ECDH_SHARED_KEY_LEN], T[CRYPTO_ECDH_SHARED_KEY_LEN] = { 0 }, tmp[CRYPTO_AES_KEY_LEN];
	uint32_t outlen = CRYPTO_ECDH_SHARED_KEY_LEN;
	int i, ret, tmplen;
	unsigned char *p;

	if (!HMAC(md, salt, CRYPTO_SALT_LEN, ecdh_shared_key, CRYPTO_ECDH_SHARED_KEY_LEN, prk, &outlen))
		return false;

	ret = CRYPTO_AES_KEY_LEN / CRYPTO_ECDH_SHARED_KEY_LEN + !!(CRYPTO_AES_KEY_LEN%CRYPTO_ECDH_SHARED_KEY_LEN);

	tmplen = outlen;
	for (i = 0; i < ret; i++)
	{
		p = tmp;

		/*T(0) = empty string (zero length)*/
		if (i != 0)
		{
			memcpy(p, T, CRYPTO_ECDH_SHARED_KEY_LEN);
			p += CRYPTO_ECDH_SHARED_KEY_LEN;
		}

		memcpy(p, info, info_len);
		p += info_len;
		*p++ = i + 1;

		HMAC(md, prk, CRYPTO_ECDH_SHARED_KEY_LEN, tmp, (int)(p - tmp), T, &outlen);
		memcpy(out + i * CRYPTO_ECDH_SHARED_KEY_LEN, T, tmplen < CRYPTO_ECDH_SHARED_KEY_LEN ? tmplen : CRYPTO_ECDH_SHARED_KEY_LEN);
		tmplen -= CRYPTO_ECDH_SHARED_KEY_LEN;
	}

	return true;
}
