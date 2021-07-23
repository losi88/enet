#include <string>
#include <vector>
#include <openssl/evp.h>
#include "openssl/ssl.h"
#include "enet/ssl/common.h"
#include "enet/protocol.h"
#include "enet/ssl/ssl_enet.h"
#include "enet/enet.h"

// static SSL_Peer* m_peers[ENET_PROTOCOL_MAXIMUM_PEER_ID];
// static EVP_CIPHER_CTX* m_cipherContext;
// static const EVP_CIPHER* m_cipherMethod;
// static unsigned int m_ivLength;
// uint8_t SSLWorkBuffer[4096];

using namespace std;

bool ssl_init(struct _ENetHost* host)
{
	OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT, NULL);

	// host -> m_cipherContext = EVP_CIPHER_CTX_new();
	// EVP_CIPHER_CTX_set_padding(host->m_cipherContext, 0);
	// host->m_cipherMethod = EVP_aes_256_cbc();
	// if (!host->m_cipherContext)
	// {
	// 	return false;
	// }

	return true;
}

void ssl_get_session_id(unsigned int peer, unsigned char* sessionId, unsigned int length)
{
#ifdef _CONSOLE
#else
	// memcpy(sessionId, GetApp()->GetENetClient()->GetSessionId(), length);
	 memcpy(sessionId, "8a8d9fa0e9f811eb9a030242ac130003", length);
#endif
}

 bool ssl_get_keymaterial_for_session_id(const unsigned char* sessionId, ownkey_s* key)
{
	if (!generate_ecdh_keys(key->ec_pub_key, key->ec_priv_key, "client"))
	{
		std::cout << "ECDH-KEY generation failed." << std::endl;
		return false;
	}
	
	if (!rand_salt(key->salt, CRYPTO_SALT_LEN))
	{
		std::cout << "Random salt generation failed." << std::endl;
		return false;
	}
	
	return true;
}

// void ssl_shut_down_peer(int index)
// {
// 	SSL_Peer* peer = get_peer(index);
// 	if (!peer)
// 	{
// 		return;
// 	}
//
// 	// LogMsg("Shutdown Peer %d", index);
// 	delete peer;
// 	m_peers[index] = nullptr;
// }

bool ssl_create_peer(struct _ENetPeer* peer, const ownkey_s* own_key, const peerkey_s* peer_key)
{
	peer->ssl_peer.state = SSL_Peer_State_HandshakeComplete;

	memcpy(peer->ssl_peer.ownkey.ec_priv_key, own_key->ec_priv_key, CRYPTO_EC_PRIV_KEY_LEN);
	memcpy(peer->ssl_peer.ownkey.ec_pub_key, own_key->ec_pub_key, CRYPTO_EC_PUB_KEY_LEN);
	memcpy(peer->ssl_peer.ownkey.salt, own_key->salt, CRYPTO_SALT_LEN);
	
	memcpy(peer->ssl_peer.peer_key.aes_key, peer_key->aes_key, CRYPTO_EC_PRIV_KEY_LEN);
	memcpy(peer->ssl_peer.peer_key.ec_pub_key, peer_key->ec_pub_key, CRYPTO_EC_PUB_KEY_LEN);
	memcpy(peer->ssl_peer.peer_key.salt, peer_key->salt, CRYPTO_SALT_LEN);

	return true;
}


int ssl_encrypt_message(unsigned int peer, const unsigned char* buffer, unsigned int inSize, unsigned char* bufferOut, unsigned int outBufferSize,
	const unsigned char *key, const unsigned char *iv, uint8_t key_len)
{
	unsigned int hmacLength = 0;
	uint8_t SSLWorkBuffer[ENET_PROTOCOL_MAXIMUM_MTU] = {0, };
	memcpy(SSLWorkBuffer, buffer, inSize);
	if (calculate_hmac(peer, buffer, inSize, SSLWorkBuffer + inSize, &hmacLength, key, key_len) > 0)
	{
		int encryptedSize = encrypt_message(peer, SSLWorkBuffer, inSize + CRYPTO_HMAC_SHA256, bufferOut, outBufferSize,
			key, iv);
		if (encryptedSize > 0)
		{
			return encryptedSize;
		}
	}

	return -1;
}

int ssl_decrypt_message(unsigned int peer, const unsigned char* buffer, unsigned int inSize, unsigned char* bufferOut, unsigned int outBufferSize,
	const unsigned char *key, const unsigned char *iv, uint8_t key_len)
{
	unsigned int hmacLength = 0;
	if (inSize < CRYPTO_HMAC_SHA256)
	{
		return -1;
	}
	
	unsigned char calculatedHmac[CRYPTO_HMAC_SHA256] = { 0, };
	
	int decryptedSize = decrypt_message(peer, buffer, inSize, bufferOut, outBufferSize, key, iv);
	if (decryptedSize > 0)
	{
		unsigned char receivedHmac[CRYPTO_HMAC_SHA256] { 0, };
		memcpy(receivedHmac, bufferOut + (decryptedSize - CRYPTO_HMAC_SHA256), CRYPTO_HMAC_SHA256);
		if (calculate_hmac(peer, bufferOut, decryptedSize - CRYPTO_HMAC_SHA256, calculatedHmac, &hmacLength, key, key_len) > 0)
		{
			if (0 == memcmp(calculatedHmac, receivedHmac, CRYPTO_HMAC_SHA256))
			{
				return decryptedSize - CRYPTO_HMAC_SHA256;
			}
		}
	}

	return -1;
}

 bool ssl_key_calculate(const ownkey_s* ownkey, peerkey_s* peerkey)
{
	/* XOR the ownkey and peerkey to one array */
	uint8_t salt_xor[CRYPTO_SALT_LEN];
	if (!bytes_xor(ownkey->salt, sizeof(ownkey_s::salt), peerkey->salt, sizeof(peerkey_s::salt), salt_xor))
	{
		std::cout << "xor calculation error." << std::endl;
		return false;
	}

	std::cout << "Calculated the final salt:" << std::endl;

	memcpy(peerkey->salt, salt_xor, CRYPTO_SALT_LEN);
	common::hex_dump(peerkey->salt, CRYPTO_SALT_LEN, std::cout);
	
	/* Calculate the shared key using own public and private keys and the public key of the other party */
	uint8_t shared_key[CRYPTO_ECDH_SHARED_KEY_LEN];
	if (!calc_ecdh_shared_key(ownkey->ec_pub_key, ownkey->ec_priv_key, peerkey->ec_pub_key, shared_key))
	{
		std::cout << "shared key calculation error." << std::endl;
		return false;
	}
	
	std::cout << "Calculated the final SHARED-KEY:" << std::endl;
	common::hex_dump(shared_key, CRYPTO_ECDH_SHARED_KEY_LEN, std::cout);
	
	/* Using HKDF to calculate the final AES key */
	if (!generate_hkdf_bytes(shared_key, salt_xor, (uint8_t*)CRYPTO_KEY_INFO, strlen(CRYPTO_KEY_INFO), peerkey->aes_key))
	{
		std::cout << "hkdf calculation error." << std::endl;
		return false;
	}
	
	std::cout << "Calculated the final AES-KEY:" << std::endl;
	common::hex_dump(peerkey->aes_key, CRYPTO_AES_KEY_LEN, std::cout);

	return true;
}