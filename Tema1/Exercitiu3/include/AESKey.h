#ifndef SITEMA1_AESKEY_H
#define SITEMA1_AESKEY_H

/**
 * AES Key interface
 */
class AESKey
{
protected:
	unsigned char* m_key = nullptr;
	unsigned char* m_iv = nullptr;
public:
	virtual ~AESKey() = default;
	virtual void setIv(const unsigned char* iv) = 0;
	virtual void setKey(const unsigned char* key) = 0;
	virtual const unsigned char* getKeyArray() = 0;
	virtual const unsigned char* getIv() = 0;
};


#endif //SITEMA1_AESKEY_H
