//OpenSSL
#include <openssl/err.h>
#include <openssl/evp.h>

//other libraries
#include <cstring>
#include <iostream>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <random>
#include <vector>


using namespace std;
using EVP_CIPHER_CTX_ptr = unique_ptr<EVP_CIPHER_CTX, decltype(&::EVP_CIPHER_CTX_free)>;

/**
 * Algorithm used in order to encrypt 128 bit blocks of data
 * @param plainText: the text to be encrypted
 * @param plainTextSize: the size of the text
 * @param iv: initialisation vector
 * @param key: the key used to encrypt the plainText
 * @param evpCipher: the cipher that we use to encrypt the text, EVP_aes_128_cbc or EVP_aes_128_ebc
 * @return a string containing the encrypted text or an empty string if an error occured
 */
string encrypt(const unsigned char *const plainText, const int &plainTextSize, const unsigned char *const iv,
               const unsigned char *const key, const EVP_CIPHER *const evpCipher)
{
	unsigned char cipherText[128] = {0};
	int len = 0;

	EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
	if (ctx == nullptr)
	{
		cout << "\nEVP_CIPHER_CTX_new failed";
		return string();
	}

	if (EVP_EncryptInit_ex(ctx.get(), evpCipher, nullptr, key, iv) != 1)
	{
		cout << "\nEVP_EncryptInit_ex failed";
		return string();
	}

	if (EVP_EncryptUpdate(ctx.get(), cipherText, &len, plainText, plainTextSize) != 1)
	{
		cout << "\nEVP_EncryptUpdate failed";
		return string();
	}

	if (EVP_EncryptFinal_ex(ctx.get(), cipherText + len, &len) != 1)
	{
		cout << "\nEVP_EncryptFinal_ex failed";
		return string();
	}

	return string(reinterpret_cast<const char *>(cipherText));
}

/**
 * Algorithm used in order to decrypt a given encrypted text supposing we have the key and iv
 * @param cryptoText: text to be decrypted
 * @param cryptoTextLength: size of the cryptoText
 * @param key: the key used to decrypt the data
 * @param iv: initialisation vector
 * @param evpCipher: the cipher used to decrypt the data, EVP_aes_128_cbc or EVP_aes_128_ebc
 * @param plainText: the decrypted text
 * @return the decrypted text or an empty string if an error occured
 */
string decrypt(const unsigned char *const cryptoText, int cryptoTextLength, const unsigned char *const key,
               const unsigned char *const iv, const EVP_CIPHER *const evpCipher, unsigned char *&plainText)
{
	int len = 0;

	EVP_CIPHER_CTX_ptr ctx(EVP_CIPHER_CTX_new(), ::EVP_CIPHER_CTX_free);
	if (ctx == nullptr)
	{
		cout << "\nEVP_CIPHER_CTX_new failed\n";
		return string();
	}

	if (1 != EVP_DecryptInit_ex(ctx.get(), evpCipher, nullptr, key, iv))
	{
		cout << "\nEVP_DecryptInit_ex failed\n";
		return string();
	}

	if (1 != EVP_DecryptUpdate(ctx.get(), plainText, &len, cryptoText, cryptoTextLength))
	{
		cout << "\nEVP_DecryptUpdate failed\n";
		return string();
	}

	int toReplace = len;
	if (1 != EVP_DecryptFinal_ex(ctx.get(), plainText + len, &len))
	{
		cout << "\nEVP_DecryptFinal_ex failed: " << ERR_error_string(ERR_get_error(), nullptr);
		return string();
	}

	//the algorithm messes up sometimes so we clean up in order to not have garbage values after the decrypted text
	memset(plainText + toReplace, 0, toReplace);
	return string(reinterpret_cast<const char *>(plainText));
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

/**
 * Helper function to read all the possible passwords from a dictionary line by line
 */
vector<string> getPossiblePasswords()
{
	ifstream passwords;
	passwords.open(WORDS_TEXT_FILE, ios::in);

	string line, password;
	vector<string> passwordVector;
	while (getline(passwords, line))
	{
		istringstream iss(line);

		if (!(iss >> password))
		{ break; }
		if (password.length() == MAX_PASSWORD_SIZE)
		{
			passwordVector.push_back(password);
		}
	}

	return passwordVector;
}

/**
 * Helper function in order to generate a random password from the dictionary
 * @param possiblePasswords: the dictionary that we use
 * @return a 16 character password from the dictionary
 */
string passwordGenerator(vector<string> possiblePasswords)
{
	cout << "\nThere are: " << possiblePasswords.size() << " password possibilities\n";

	random_device seeder;
	mt19937 engine(seeder());
	uniform_int_distribution<int> dist(0, possiblePasswords.size());

	int randomChoice = dist(engine);
	string completePassword = possiblePasswords[randomChoice] + " ";

	return completePassword;
}

/**
 * Algorithm used to crack an encrypted text using all the possibilities until the encrypted text is deciphered
 * @param possiblePasswords: all the possible passwords in the given dictionary
 * @param iv: initialisation vector
 * @param evpCipher: the cipher used to decrypt the data
 * @return a string containing the deciphered text or a empty string if no solution is found
 */
string bruteForce(const vector<string>& possiblePasswords, const unsigned char *const iv, const EVP_CIPHER *const evpCipher)
{
	//read the encrypted text from CRYPTO_TEXT_FILE
	string encryptedText = readFromFile(CRYPTO_TEXT_FILE);

	//brute force attack in order to find the key used for the encryption
	string decryptedText, possibleCompleteKey;
	auto response = new unsigned char[128]{0};
	bool badDecrypt = false;

	//for each possible password check if the decryption algorithm works
	for (const auto &possiblePassword : possiblePasswords)
	{
		possibleCompleteKey = possiblePassword + " ";
		decryptedText = decrypt(reinterpret_cast<const unsigned char *const>(encryptedText.c_str()),
		                        encryptedText.length(),
		                        reinterpret_cast<const unsigned char *const>(possibleCompleteKey.c_str()), iv,
		                        evpCipher, response);

		//if the decrypted text is not empty we check for a false positive
		if (!decryptedText.empty())
		{
			//if the characters are not simple ASCII characters we switch the badDecrypt to true
			for (size_t character = 0; character < decryptedText.length(); character++)
			{
				if ((int) decryptedText[character] < 32 || (int) decryptedText[character] > 126)
				{
					badDecrypt = true;
					break;
				}
			}
			//or if the text is too short we also switch the flag
			if (decryptedText.length() <= 3)
			{
				badDecrypt = true;
			}

			//if we get here it means that the text was decrypted successfully
			if (!badDecrypt)
			{
				cout << "\n/////TEXT DECRYPTED/////\nDecrypted text is: " << decryptedText << "\nKey is: "
				     << possibleCompleteKey << "\n";
				return decryptedText;
			}
		}
		decryptedText.clear();
		badDecrypt = false;
	}

	return string();
}

int main()
{
	ERR_load_crypto_strings();

	//read the plaintext
	string plainText = readFromFile(PLAIN_TEXT_FILE);
	if(plainText.empty())
	{
		cout<<"Could not complete the algorithm";
		return 1;
	}

	//generate a random password
	vector<string> possiblePasswords = getPossiblePasswords();
	string password = passwordGenerator(possiblePasswords);

	//provided key and iv
	auto key = reinterpret_cast<const unsigned char *const>(password.c_str());
	auto iv = reinterpret_cast<const unsigned char *const>("\x21\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f");

	//where the cipher text will be written
	//BIO = Byte Input/Output
	BIO *cryptoBio = BIO_new_file(CRYPTO_TEXT_FILE, "w");

	//cipher used to encrypt the data
	const EVP_CIPHER *const evpCipher = EVP_aes_128_cbc();
	//const EVP_CIPHER* const evpCipher = EVP_aes_128_ecb();

	//algorithm used to encrypt blocks of 128 bytes of data
	string cryptoTextString = encrypt(reinterpret_cast<const unsigned char *const>(plainText.c_str()),
	                                  plainText.length(), iv, key, evpCipher);

	//write the data in CRYPTO_TEXT_FILE
	BIO_printf(cryptoBio, "%s", cryptoTextString.c_str());
	BIO_free(cryptoBio);

	bruteForce(possiblePasswords, iv, evpCipher);
	return 0;
}