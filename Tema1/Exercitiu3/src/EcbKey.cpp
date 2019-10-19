#include <cstring>
#include "EcbKey.h"

void EcbKey::setIv(const unsigned char *iv)
{
	memset(this->m_iv, 0, INIT_VEC_LENGTH);
	memcpy(this->m_iv, iv, INIT_VEC_LENGTH);
}

void EcbKey::setKey(const unsigned char *key)
{
	memset(this->m_key, 0, KEY_LENGTH);
	memcpy(this->m_key, key, KEY_LENGTH);
}

const unsigned char *EcbKey::getKeyArray()
{
	return this->m_key;
}

const unsigned char *EcbKey::getIv()
{
	return this->m_iv;
}

EcbKey::~EcbKey()
{
	delete[] m_iv;
	delete[] m_key;
}

EcbKey EcbKey::getKey()
{
	return *this;
}

EcbKey::EcbKey(const unsigned char *iv, const unsigned char *key)
{
	this->m_iv = new unsigned char[INIT_VEC_LENGTH];
	this->m_key = new unsigned char[KEY_LENGTH];

	setKey(key);
	setIv(iv);
}
