#include "enet/ssl/ssl_enet.h"

#include <string>
#include <vector>
#include <openssl/evp.h>
#include "openssl/ssl.h"
#include "enet/ssl/common.h"

uint8_t SSLWorkBuffer[4096];
SSL_Peer*				m_peers[MAX_PEERS];
EVP_CIPHER_CTX*			m_cipherContext;
const EVP_CIPHER*       m_cipherMethod;
unsigned int			m_ivLength;

using namespace std;

bool ssl_init()
{
	memset(m_peers, 0, sizeof(m_peers));
	
	OPENSSL_init_ssl(OPENSSL_INIT_SSL_DEFAULT, NULL);

	m_cipherContext = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_set_padding(m_cipherContext, 0);
	if (!m_cipherContext)
	{
		return false;
	}

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

void ssl_shut_down_peer(int index)
{
	SSL_Peer* peer = get_peer(index);
	if (!peer)
	{
		return;
	}

	// LogMsg("Shutdown Peer %d", index);
	delete peer;
	m_peers[index] = nullptr;
}

int ssl_create_peer(const ownkey_s* own_key, const peerkey_s* peer_key)
{
	int index = get_new_peer();
	if (index < 0)
	{
		// LogMsg("Not Enough Space for new Peers");
		return -1;
	}
	else
	{
		// LogMsg("Create Peer %d", index);
	}

	SSL_Peer* peer = new SSL_Peer;

	peer->state = SSL_Peer_State_HandshakeComplete;

	memcpy(peer->ownkey.ec_priv_key, own_key->ec_priv_key, CRYPTO_EC_PRIV_KEY_LEN);
	memcpy(peer->ownkey.ec_pub_key, own_key->ec_pub_key, CRYPTO_EC_PUB_KEY_LEN);
	memcpy(peer->ownkey.salt, own_key->salt, CRYPTO_SALT_LEN);
	
	memcpy(peer->peer_key.aes_key, peer_key->aes_key, CRYPTO_EC_PRIV_KEY_LEN);
	memcpy(peer->peer_key.ec_pub_key, peer_key->ec_pub_key, CRYPTO_EC_PUB_KEY_LEN);
	memcpy(peer->peer_key.salt, peer_key->salt, CRYPTO_SALT_LEN);
	
	m_peers[index] = peer;
	m_cipherMethod = EVP_aes_256_cbc();
	
	set_iv_length(EVP_CIPHER_iv_length(m_cipherMethod));
	return index;
}


int ssl_encrypt_message(unsigned int peer, const unsigned char* buffer, unsigned int inSize, unsigned char* bufferOut, unsigned int outBufferSize,
	const unsigned char *key, const unsigned char *iv, uint8_t key_len)
{
	unsigned int hmacLength = 0;
	memcpy(SSLWorkBuffer, buffer, inSize);
	//if (CalculateHMAC(peer, buffer, inSize, SSLWorkBuffer + inSize, hmacLength, key, key_len) > 0)
	//{
	//	int encryptedSize = EncryptMessage(peer, SSLWorkBuffer, inSize + 32, bufferOut, outBufferSize,
	//		key, iv);
	//	if (encryptedSize > 0)
	//	{
	//		return encryptedSize;
	//	}
	//}
	// int encryptedSize = encrypt_message(peer, SSLWorkBuffer, inSize + 32, bufferOut, outBufferSize, key, iv);
	common::hex_dump(key, CRYPTO_AES_KEY_LEN, std::cout);
	common::hex_dump(iv, CRYPTO_SALT_LEN, std::cout);
	int encryptedSize = encrypt_message(peer, SSLWorkBuffer, inSize, bufferOut, outBufferSize, key, iv);
	return encryptedSize;
}

int ssl_decrypt_message(unsigned int peer, const unsigned char* buffer, unsigned int inSize, unsigned char* bufferOut, unsigned int outBufferSize,
	const unsigned char *key, const unsigned char *iv, uint8_t key_len)
{
	unsigned int hmacLength = 0;
	// std::string calculatedHmac;
	// calculatedHmac.resize(32);

	common::hex_dump(key, CRYPTO_AES_KEY_LEN, std::cout);
	common::hex_dump(iv, CRYPTO_SALT_LEN, std::cout);
	int decryptedSize = decrypt_message(peer, buffer, inSize, bufferOut, outBufferSize, key, iv);

	return decryptedSize;
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

	memcpy(peerkey->salt, salt_xor, CRYPTO_SALT_LEN);
	
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
