#ifndef SITEMA1_CBCKEY_H
#define SITEMA1_CBCKEY_H

#include "AESKey.h"

/**
 * In CBC mode, each block of plaintext is XORed with the previous cipher text block before being encrypted.
 * This way, each cipher text block depends on all plaintext blocks processed up to that point.
 * To make each message unique, an initialization vector must be used in the first block.
 * Decrypting with the incorrect IV causes the first block of plaintext to be corrupt but subsequent plaintext
 * blocks will be correct.
 * This is because each block is XORed with the ciphertext of the previous block,
 * not the plaintext, so one does not need to decrypt the previous block before using it as the IV for the decryption
 * of the current one. This means that a plaintext block can be recovered from two adjacent blocks of cipher text.
 */
class CbcKey : public AESKey
{
public:
	CbcKey(const unsigned char* iv, const unsigned char* key);
	~CbcKey() override;

	CbcKey getKey();
	void setIv(const unsigned char *iv) override;
	void setKey(const unsigned char *key) override;
	const unsigned char *getKeyArray() override;
	const unsigned char *getIv() override;
};


#endif //SITEMA1_CBCKEY_H
