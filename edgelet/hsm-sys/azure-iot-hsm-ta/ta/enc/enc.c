/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <openenclave/enclave.h>
#include <openenclave/bits/stdio.h>
#include "common.h"
#include "enc_t.h"

// TODO: add error logging for failure conditions in ecalls

#define MASTER_ENCRYPTION_KEY_FILE_PATH "/PKI/keys/edgelet-master.enc.key"
#define MASTER_ENCRYPTION_KEY_SIZE_BYTES 32

#define IDENTITY_KEY_FILE_PATH "/PKI/keys/edgelet-identity.enc.key"

int get_master_encryption_key(unsigned char* key)
{
	OE_FILE* key_file;

	if ((key_file = oe_fopen(
		OE_FILE_SECURE_BEST_EFFORT,
		MASTER_ENCRYPTION_KEY_FILE_PATH,
		"r")) == NULL)
	{
		return 1;
	}

	if (oe_fread(key, 1, MASTER_ENCRYPTION_KEY_SIZE_BYTES, key_file) !=
		MASTER_ENCRYPTION_KEY_SIZE_BYTES)
	{
		oe_fclose(key_file);
		return 1;
	}

	oe_fclose(key_file);
	return 0;
}

int get_identity_key(unsigned char** key, size_t* key_len)
{
	OE_FILE* key_file;

	if ((key_file = oe_fopen(
		OE_FILE_SECURE_BEST_EFFORT,
		IDENTITY_KEY_FILE_PATH,
		"r")) == NULL)
	{
		return 1;
	}

	oe_fseek(key_file, 0, 2);
	*key_len = oe_ftell(key_file);
	oe_fseek(key_file, 0, 0);

	if ((*key = malloc(*key_len)) == NULL)
	{
		oe_fclose(key_file);
		return 1;
	}

	if (oe_fread(*key, 1, *key_len, key_file) != *key_len)
	{
		oe_fclose(key_file);
		return 1;
	}

	oe_fclose(key_file);
	return 0;
}

int ecall_TaGetRandomBytes(unsigned char* buffer, size_t buffer_size)
{
	return oe_random(buffer, buffer_size) == OE_OK ? 0 : 1;
}

int ecall_TaCreateMasterEncryptionKey()
{
	unsigned char key[MASTER_ENCRYPTION_KEY_SIZE_BYTES];
	OE_FILE* key_file;

	if (oe_random(key, MASTER_ENCRYPTION_KEY_SIZE_BYTES) != OE_OK)
	{
		return 1;
	}

	if ((key_file = oe_fopen(
		OE_FILE_SECURE_BEST_EFFORT,
		MASTER_ENCRYPTION_KEY_FILE_PATH,
		"w")) == NULL)
	{
		return 1;
	}

	if (oe_fwrite(key, 1, MASTER_ENCRYPTION_KEY_SIZE_BYTES, key_file) !=
		MASTER_ENCRYPTION_KEY_SIZE_BYTES)
	{
		oe_fclose(key_file);
		return 1;
	}

	oe_fclose(key_file);
	return 0;
}

int ecall_TaDestroyMasterEncryptionKey()
{
	return oe_remove(
		OE_FILE_SECURE_BEST_EFFORT, MASTER_ENCRYPTION_KEY_FILE_PATH);
}

int ecall_TaEncryptData(
	const unsigned char* plaintext,
	size_t plaintext_len,
	const unsigned char* aad,
	size_t aad_len,
	const unsigned char* iv,
	size_t iv_len,
	unsigned char* output_buffer,
	size_t output_buffer_size)
{
	mbedtls_gcm_context gcm;
	unsigned char key[MASTER_ENCRYPTION_KEY_SIZE_BYTES];
	unsigned char* version = output_buffer;
	unsigned char* tag = output_buffer + CIPHER_VERSION_SIZE_BYTES;
	unsigned char* ciphertext = output_buffer + CIPHER_HEADER_V1_SIZE_BYTES;

	if (plaintext == NULL || aad == NULL || iv == NULL || output_buffer == NULL)
	{
		return 1;
	}

	if (output_buffer_size < plaintext_len + CIPHER_HEADER_V1_SIZE_BYTES)
	{
		return 1;
	}

	if (get_master_encryption_key(key) != 0)
	{
		return 1;
	}

	mbedtls_gcm_init(&gcm);
	if (mbedtls_gcm_setkey(
		&gcm,
		MBEDTLS_CIPHER_ID_AES,
		key,
		MASTER_ENCRYPTION_KEY_SIZE_BYTES * 8) != 0)
	{
		return 1;
	}

	*version = CIPHER_VERSION_V1;
	if (mbedtls_gcm_crypt_and_tag(
		&gcm,
		MBEDTLS_GCM_ENCRYPT,
		plaintext_len,
		iv,
		iv_len,
		aad,
		aad_len,
		plaintext,
		ciphertext,
		CIPHER_TAG_V1_SIZE_BYTES,
		tag) != 0)
	{
		return 1;
	}

	return 0;
}

int ecall_TaDecryptData(
	const unsigned char* ciphertext_buffer,
	size_t ciphertext_buffer_size,
	const unsigned char* aad,
	size_t aad_len,
	const unsigned char* iv,
	size_t iv_len,
	unsigned char* output_buffer,
	size_t output_buffer_size)
{
	mbedtls_gcm_context gcm;
	unsigned char key[MASTER_ENCRYPTION_KEY_SIZE_BYTES];
	const unsigned char* version = ciphertext_buffer;
	const unsigned char* tag = ciphertext_buffer + CIPHER_VERSION_SIZE_BYTES;
	const unsigned char* ciphertext = ciphertext_buffer + CIPHER_HEADER_V1_SIZE_BYTES;
	size_t ciphertext_size =
		ciphertext_buffer_size - CIPHER_HEADER_V1_SIZE_BYTES;

	if (ciphertext_buffer == NULL || aad == NULL || iv == NULL || output_buffer == NULL)
	{
		return 1;
	}

	if (output_buffer_size < ciphertext_size)
	{
		return 1;
	}

	if (*version != CIPHER_VERSION_V1)
	{
		return 1;
	}

	if (get_master_encryption_key(key) != 0)
	{
		return 1;
	}

	mbedtls_gcm_init(&gcm);
	if (mbedtls_gcm_setkey(
		&gcm,
		MBEDTLS_CIPHER_ID_AES,
		key,
		MASTER_ENCRYPTION_KEY_SIZE_BYTES * 8) != 0)
	{
		return 1;
	}

	if (mbedtls_gcm_auth_decrypt(
		&gcm,
		ciphertext_size,
		iv,
		iv_len,
		aad,
		aad_len,
		tag,
		CIPHER_TAG_V1_SIZE_BYTES,
		ciphertext,
		output_buffer) != 0)
	{
		return 1;
	}

	return 0;
}

int ecall_TaSetSigningKey(
	const unsigned char* key,
	size_t key_len)
{
	OE_FILE* key_file;

	if (key == NULL)
	{
		return 1;
	}

	if ((key_file = oe_fopen(
		OE_FILE_SECURE_BEST_EFFORT,
		IDENTITY_KEY_FILE_PATH,
		"w")) == NULL)
	{
		return 1;
	}

	if (oe_fwrite(key, 1, key_len, key_file) !=
		key_len)
	{
		oe_fclose(key_file);
		return 1;
	}

	oe_fclose(key_file);
	return 0;
}

int ecall_TaSignData(
	const unsigned char* data_to_be_signed,
	size_t data_to_be_signed_size,
	unsigned char* digest,
	size_t digest_size)
{
	int result = 0;
	unsigned char* key = NULL;
	size_t key_len;

	if (data_to_be_signed == NULL || digest == NULL)
	{
		return 1;
	}

	if (digest_size < MD_OUTPUT_SIZE)
	{
		return 1;
	}

	if (get_identity_key(&key, &key_len) != 0)
	{
		result = 1;
		goto exit;
	}

	// TODO: use the TPM for this
	if (mbedtls_md_hmac(
		mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
		key,
		key_len,
		data_to_be_signed,
		data_to_be_signed_size,
		digest) != 0)
	{
		result = 1;
		goto exit;
	}

exit:
	if (key != NULL)
	{
		free(key);
	}
	return result;
}

int ecall_TaDeriveAndSignData(
	const unsigned char* identity,
	size_t identity_size,
	const unsigned char* data_to_be_signed,
	size_t data_to_be_signed_size,
	unsigned char* digest,
	size_t digest_size)
{
	int result = 0;
	unsigned char* key = NULL;
	size_t key_len;
	unsigned char derived_identity[MD_OUTPUT_SIZE];

	if (identity == NULL || data_to_be_signed == NULL || digest == NULL)
	{
		return 1;
	}

	if (digest_size < MD_OUTPUT_SIZE)
	{
		return 1;
	}

	if (get_identity_key(&key, &key_len) != 0)
	{
		result = 1;
		goto exit;
	}

	// TODO: use the TPM for this
	if (mbedtls_md_hmac(
		mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
		key,
		key_len,
		identity,
		identity_size,
		derived_identity) != 0)
	{
		result = 1;
		goto exit;
	}

	if (mbedtls_md_hmac(
		mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
		derived_identity,
		MD_OUTPUT_SIZE,
		data_to_be_signed,
		data_to_be_signed_size,
		digest) != 0)
	{
		result = 1;
		goto exit;
	}

exit:
	if (key != NULL)
	{
		free(key);
	}
	return result;

}
