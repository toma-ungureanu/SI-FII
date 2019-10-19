#ifndef SITEMA1_ECBKEY_H
#define SITEMA1_ECBKEY_H


#include "AESKey.h"
/**
 * The message is divided into blocks, and each block is encrypted separately.
 * The disadvantage of this method is a lack of diffusion. Because ECB encrypts identical plaintext blocks into
 * identical cipher text blocks, it does not hide data patterns well.
 * In some senses, it doesn't provide serious message confidentiality, and it is not recommended for use in
 * cryptographic protocols at all.
 */
class EcbKey : public AESKey
{
public:
	EcbKey(const unsigned char* iv, const unsigned char* key);

	~EcbKey() override;
	EcbKey getKey();
	void setIv(const unsigned char *iv) override;
	void setKey(const unsigned char *key) override;
	const unsigned char *getKeyArray() override;
	const unsigned char *getIv() override;
};


#endif //SITEMA1_ECBKEY_H
