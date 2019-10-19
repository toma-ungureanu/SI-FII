#ifndef SITEMA1_KEYMANAGER_H
#define SITEMA1_KEYMANAGER_H


#include <openssl/evp.h>
#include "AESKey.h"
#include "CbcKey.h"
#include "EcbKey.h"
#include "CtrKey.h"
#include <string>

using namespace std;

class KeyManager
{
private:
	AESKey* m_key1{};
	AESKey* m_key2{};
	AESKey* m_key3{};
	string m_opMode;
	const EVP_CIPHER *const m_evpCipher = EVP_aes_256_ctr();

public:
	KeyManager(AESKey*& key1, AESKey*& key2, AESKey*& key3);

	KeyManager() = default;

	[[nodiscard]] AESKey* getKey1();

	[[nodiscard]] AESKey* getKey2();

	[[nodiscard]] AESKey* getKey3();

	[[nodiscard]] const EVP_CIPHER *getEvpCipher() const;

	[[nodiscard]] string &getOpMode();

	void setKey1(AESKey* key1);

	void setKey2(AESKey* key2);

	void setKey3(AESKey* key3);

	void setOpMode(const string &mOpMode);
};


#endif //SITEMA1_KEYMANAGER_H
