#ifndef __ENET_SSL_SSL_ENET_H__
#define __ENET_SSL_SSL_ENET_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "enet/ssl/ecdh.h"
#include "openssl/asn1.h"

typedef struct _ownkey_s {
	uint8_t ec_pub_key[CRYPTO_EC_PUB_KEY_LEN];
	uint8_t ec_priv_key[CRYPTO_EC_PRIV_KEY_LEN];
	uint8_t salt[CRYPTO_SALT_LEN];            // Just use in key exchange
} ownkey_s;

typedef struct _peerkey_s {
	uint8_t ec_pub_key[CRYPTO_EC_PUB_KEY_LEN];
	uint8_t aes_key[CRYPTO_AES_KEY_LEN];
	uint8_t salt[CRYPTO_SALT_LEN];            // Just use in key exchange
} peerkey_s;

typedef enum _EPeerState
{
	SSL_Peer_State_None,
	SSL_Peer_State_HandshakeInProgress,
	SSL_Peer_State_HandshakeComplete
} EPeerState;

typedef struct _SSL_Peer
{
	EPeerState	state;
	ownkey_s	ownkey;
	peerkey_s	peer_key;
} SSL_Peer;

struct _ENetHost;
	
bool ssl_init(struct _ENetHost* host);
void ssl_get_session_id(unsigned int peer, unsigned char* sessionId, unsigned int length);
bool ssl_get_keymaterial_for_session_id(const unsigned char* sessionId, ownkey_s* key);
// void ssl_shut_down_peer(int index);
bool ssl_create_peer(struct _ENetPeer* peer, const ownkey_s* own_key, const peerkey_s* peer_key);

int ssl_encrypt_message(unsigned int peer, const unsigned char* buffer, unsigned int inSize, unsigned char* bufferOut, unsigned int outBufferSize,
	const unsigned char *key, const unsigned char *iv, uint8_t key_len);

int ssl_decrypt_message(unsigned int peer, const unsigned char* buffer, unsigned int inSize, unsigned char* bufferOut, unsigned int outBufferSize,
	const unsigned char *key, const unsigned char *iv, uint8_t key_len);

bool ssl_key_calculate(const ownkey_s* ownkey, peerkey_s* peerkey);
#ifdef __cplusplus
}
#endif
#endif
