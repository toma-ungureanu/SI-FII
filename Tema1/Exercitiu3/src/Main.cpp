#include <openssl/evp.h>
#include <openssl/ossl_typ.h>

#include <openssl/err.h>
#include <memory>

#include <iostream>
#include <random>
#include <algorithm>
#include <cstring>
#include <fstream>

#include "CommNode.h"
#include "KeyManager.h"
#include "AESKey.h"
#include "CbcKey.h"
#include "CtrKey.h"
#include "EcbKey.h"

using namespace std;
using EVP_CIPHER_CTX_ptr = unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

vector<unsigned char> generateRandomBytes(int size)
{
	std::random_device dev;
	std::mt19937 rng(dev());
	vector<unsigned char> data(size);
	generate(begin(data), end(data), std::ref(rng));

	return data;
}

/**
 * Algorithm used in order to encrypt data
 * @param plainText: the text to be encrypted
 * @param plainTextSize: the size of the text
 * @param iv: initialisation vector
 * @param key: the key used to encrypt the plainText
 * @param evpCipher: the cipher that we use to encrypt the text, EVP_aes_256_cbc or EVP_aes_256_ebc
 * @return a string containing the encrypted text or an empty string if an error occured
 */
unsigned char *encrypt(const unsigned char *plainText, const int &plainTextSize, const unsigned char *const iv,
                       const unsigned char *const key, const EVP_CIPHER *const evpCipher)
{
	auto cipherText = new unsigned char[KEY_LENGTH]{};
	int len = 0;

	EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
	if (ctx == nullptr)
	{
		cout << "\nEVP_CIPHER_CTX_new failed";
		return nullptr;
	}

	if (EVP_EncryptInit_ex(ctx.get(), evpCipher, nullptr, key, iv) != 1)
	{
		cout << "\nEVP_EncryptInit_ex failed";
		return nullptr;
	}

	if (EVP_EncryptUpdate(ctx.get(), cipherText, &len, plainText, plainTextSize) != 1)
	{
		cout << "\nEVP_EncryptUpdate failed";
		return nullptr;
	}

	if (EVP_EncryptFinal_ex(ctx.get(), cipherText + len, &len) != 1)
	{
		cout << "\nEVP_EncryptFinal_ex failed";
		return nullptr;
	}

	return cipherText;
}

/**
 * Algorithm used in order to decrypt a given encrypted text supposing we have the key and iv
 * @param cryptoText: text to be decrypted
 * @param cryptoTextLength: size of the cryptoText
 * @param key: the key used to decrypt the data
 * @param iv: initialisation vector
 * @param evpCipher: the cipher used to decrypt the data, EVP_aes_256_cbc or EVP_aes_256_ebc
 * @param plainText: the decrypted text
 * @return the decrypted text or an empty string if an error occured
 */
unsigned char *decrypt(const unsigned char *cryptoText, int cryptoTextLength, const unsigned char *const key,
                       const unsigned char *const iv, const EVP_CIPHER *const evpCipher)
{
	int len = 0;
	auto plainText = new unsigned char[2 * KEY_LENGTH]{};

	EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
	if (ctx == nullptr)
	{
		cout << "\nEVP_CIPHER_CTX_new failed\n";
		return nullptr;
	}

	if (1 != EVP_DecryptInit_ex(ctx.get(), evpCipher, nullptr, key, iv))
	{
		cout << "\nEVP_DecryptInit_ex failed\n";
		return nullptr;
	}

	if (1 != EVP_DecryptUpdate(ctx.get(), plainText, &len, cryptoText, cryptoTextLength))
	{
		cout << "\nEVP_DecryptUpdate failed\n";
		return nullptr;
	}

	int toReplace = len;
	if (1 != EVP_DecryptFinal_ex(ctx.get(), plainText + len, &len))
	{
		cout << "\nEVP_DecryptFinal_ex failed: " << ERR_error_string(ERR_get_error(), nullptr);
		return nullptr;
	}

	//the algorithm messes up sometimes so we clean up in order to not have garbage values after the decrypted text
	memset(plainText + toReplace, 0, toReplace);
	return plainText;
}

/**
 * Simple helper function to read from file
 * @param filename: the file from which we want to read
 * @return a string containing the text that was read
 */
string readFromFile(const string &filename)
{
	ifstream streamBuff;
	streamBuff.open(filename, ios::in);
	streamBuff.seekg(0, ios::end);
	string buffer;
	const int plainTextSize = streamBuff.tellg();
	if(plainTextSize <= 0)
	{
		cout<<"Could not read from file";
		return string();
	}
	buffer.reserve(plainTextSize);
	streamBuff.seekg(0, ios::beg);
	buffer.assign((istreambuf_iterator<char>(streamBuff)), istreambuf_iterator<char>());
	streamBuff.close();

	return buffer;
}

int main()
{
	CommNode A;
	CommNode B;

	string opMode = "cbc";

	//set the operating mode for the first node
	A.setOpMode(opMode);

	//send a message from the first node to the second one regarding the operating mode used
	B.setMessage((unsigned char *) A.getOpMode().c_str());

	//set the provisioned key for the nodes(generated randomly each time)
	AESKey *k3 = new CtrKey(generateRandomBytes(KEY_LENGTH).data(), generateRandomBytes(INIT_VEC_LENGTH).data());
	A.setProvKey(const_cast<AESKey *>(k3));
	B.setProvKey(const_cast<AESKey *>(k3));

	//create the keyManager and assign its possible keys(generated randomly)
	AESKey *k1 = new EcbKey(generateRandomBytes(KEY_LENGTH).data(), generateRandomBytes(INIT_VEC_LENGTH).data());
	AESKey *k2 = new CbcKey(generateRandomBytes(KEY_LENGTH).data(), generateRandomBytes(INIT_VEC_LENGTH).data());
	KeyManager keyManager(k1, k2, k3);

	//Node B sends a message to the key manager about the operating mode
	keyManager.setOpMode(B.getOpMode());

	AESKey *usedKey = nullptr;
	AESKey *decryptedKeyA = nullptr;
	AESKey *decryptedKeyB = nullptr;
	if (keyManager.getOpMode() == "ecb")
	{
		//encrypt the keys with the provisioned one
		k1->setKey(encrypt(k1->getKeyArray(), KEY_LENGTH, keyManager.getKey3()->getIv(),
		                   keyManager.getKey3()->getKeyArray(), keyManager.getEvpCipher()));

		k1->setIv(encrypt(k1->getKeyArray(), INIT_VEC_LENGTH, keyManager.getKey3()->getIv(),
		                  keyManager.getKey3()->getKeyArray(), keyManager.getEvpCipher()));

		usedKey = new EcbKey(k1->getIv(), k1->getKeyArray());

		//decrypt the key with the provisioned one for the first node
		decryptedKeyA = new EcbKey(
				decrypt(usedKey->getKeyArray(), KEY_LENGTH, A.getProvKey()->getKeyArray(),
				        A.getProvKey()->getIv(), keyManager.getEvpCipher()),
				decrypt(usedKey->getIv(), INIT_VEC_LENGTH, A.getProvKey()->getKeyArray(),
				        A.getProvKey()->getIv(), keyManager.getEvpCipher()));

		//decrypt the key with the provisioned one for the second node
		decryptedKeyB = new EcbKey(
				decrypt(usedKey->getKeyArray(), KEY_LENGTH, B.getProvKey()->getKeyArray(),
				        B.getProvKey()->getIv(), keyManager.getEvpCipher()),
				decrypt(usedKey->getIv(), INIT_VEC_LENGTH, B.getProvKey()->getKeyArray(),
				        B.getProvKey()->getIv(), keyManager.getEvpCipher()));
	}
	else if (keyManager.getOpMode() == "cbc")
	{
		//encrypt the keys with the provisioned one
		k2->setKey(encrypt(k1->getKeyArray(), KEY_LENGTH, keyManager.getKey3()->getIv(),
		                   keyManager.getKey3()->getKeyArray(), keyManager.getEvpCipher()));

		k2->setIv(encrypt(k1->getKeyArray(), INIT_VEC_LENGTH, keyManager.getKey3()->getIv(),
		                  keyManager.getKey3()->getKeyArray(), keyManager.getEvpCipher()));

		usedKey = new CbcKey(k1->getIv(), k1->getKeyArray());

		//decrypt the key with the provisioned one for the first node
		decryptedKeyA = new CbcKey(
				decrypt(usedKey->getKeyArray(), KEY_LENGTH, A.getProvKey()->getKeyArray(),
				        A.getProvKey()->getIv(), keyManager.getEvpCipher()),
				decrypt(usedKey->getIv(), INIT_VEC_LENGTH, A.getProvKey()->getKeyArray(),
				        A.getProvKey()->getIv(), keyManager.getEvpCipher()));

		//decrypt the key with the provisioned one for the second node
		decryptedKeyB = new CbcKey(
				decrypt(usedKey->getKeyArray(), KEY_LENGTH, B.getProvKey()->getKeyArray(),
				        B.getProvKey()->getIv(), keyManager.getEvpCipher()),
				decrypt(usedKey->getIv(), INIT_VEC_LENGTH, B.getProvKey()->getKeyArray(),
				        B.getProvKey()->getIv(), keyManager.getEvpCipher()));
	}

	A.setKey(decryptedKeyA);
	B.setKey(decryptedKeyB);

	//send message from node B to node A to start the communication safely
	B.setMessage((unsigned char *) "Done!");
	A.setMessage(const_cast<unsigned char *>(B.getMessage()));

	A.setMessage((unsigned char *) readFromFile(MESSAGE_FILE).c_str());
	unsigned char* messageToSend = encrypt(A.getMessage(),
			strlen(reinterpret_cast<const char *>(A.getMessage())),
			A.getKey()->getIv(),
			A.getKey()->getKeyArray(),
			keyManager.getEvpCipher());

	A.setMessage(messageToSend);

	B.setMessage(const_cast<unsigned char *>(A.getMessage()));
	unsigned char* decryptedMessage = (decrypt(messageToSend,
			strlen(reinterpret_cast<const char *>(B.getMessage())),
			B.getKey()->getKeyArray(),
			B.getKey()->getIv(),
			keyManager.getEvpCipher()));

	B.setMessage(decryptedMessage);
	cout<<B.getMessage();
	return 0;
}
























