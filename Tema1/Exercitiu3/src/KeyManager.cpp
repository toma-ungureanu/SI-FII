#include "KeyManager.h"

AESKey* KeyManager::getKey1()
{
	return m_key1;
}

void KeyManager::setKey1(AESKey* key1)
{
	m_key1 = key1;
}

AESKey* KeyManager::getKey2()
{
	return m_key2;
}

AESKey* KeyManager::getKey3()
{
	return m_key3;
}

void KeyManager::setKey3(AESKey *key3)
{
	m_key3 = key3;
}

void KeyManager::setKey2(AESKey* key2)
{
	m_key2 = key2;
}

string &KeyManager::getOpMode()
{
	return m_opMode;
}

void KeyManager::setOpMode(const string &opMode)
{
	m_opMode = opMode;
}

KeyManager::KeyManager(AESKey *&key1, AESKey *&key2, AESKey *&key3)
{
	m_key1 = key1;
	m_key2 = key2;
	m_key3 = key3;
}

const EVP_CIPHER *KeyManager::getEvpCipher() const
{
	return m_evpCipher;
}
