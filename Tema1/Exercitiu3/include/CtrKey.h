#ifndef SITEMA1_CTRKEY_H
#define SITEMA1_CTRKEY_H


#include "AESKey.h"

/**
 *  Counter mode turns a block cipher into a stream cipher. It generates the next key stream block by encrypting
 *  successive values of a "counter".
 *  The counter can be any function which produces a sequence which is guaranteed not to repeat for a long time,
 *  although an actual increment-by-one counter is the simplest and most popular.
 *
 *  If the IV/nonce is random, then they can be combined together with the counter using any invertible operation
 *  (concatenation, addition, or XOR) to produce the actual unique counter block for encryption.
 *  In case of a non-random nonce (such as a packet counter), the nonce and counter should be concatenated (
 *  e.g., storing the nonce in the upper 64 bits and the counter in the lower 64 bits of a 128-bit counter block).
 *  Simply adding or XORing the nonce and counter into a single value would break the security under a chosen-plaintext
 *  attack in many cases, since the attacker may be able to manipulate the entire IV–counter pair to cause a collision.
 *  Once an attacker controls the IV–counter pair and plaintext, XOR of the cipher text with the known plaintext would
 *  yield a value that, when XORed with the cipher text of the other block sharing the same IV–counter pair,
 *  would decrypt that block.
 */
class CtrKey : public AESKey
{
private:

public:
	CtrKey(const unsigned char* iv, const unsigned char* key);
	~CtrKey() override;

	void setIv(const unsigned char* iv) override;
	void setKey(const unsigned char* key) override;
	const unsigned char* getIv() override ;
	const unsigned char* getKeyArray() override ;
	CtrKey getKey();
};


#endif //SITEMA1_CTRKEY_H
