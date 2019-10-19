#include <cstring>
#include "CtrKey.h"

const unsigned char *CtrKey::getKeyArray()
{
	return this->m_key;
}

const unsigned char *CtrKey::getIv()
{
	return this->m_iv;
}

CtrKey CtrKey::getKey()
{
	return *this;
}

void CtrKey::setKey(const unsigned char *const newKey)
{
	memset(this->m_key, 0, KEY_LENGTH);
	memcpy(this->m_key, newKey, KEY_LENGTH);
}

void CtrKey::setIv(const unsigned char *newIv)
{
	memset(this->m_iv, 0, INIT_VEC_LENGTH);
	memcpy(this->m_iv, newIv, INIT_VEC_LENGTH);
}

CtrKey::~CtrKey()
{
	delete[] m_iv;
	delete[] m_key;
}

CtrKey::CtrKey(const unsigned char *const iv, const unsigned char *const key)
{
	this->m_iv = new unsigned char[INIT_VEC_LENGTH];
	this->m_key = new unsigned char[KEY_LENGTH];

	setKey(key);
	setIv(iv);
}


