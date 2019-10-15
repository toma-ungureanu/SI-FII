//OpenSSL
#include <openssl/evp.h>

//other libraries
#include <cstring>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>

using namespace std;

/**
 * Helper function to read from file
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
	buffer.reserve(plainTextSize);
	streamBuff.seekg(0, ios::beg);
	buffer.assign((istreambuf_iterator<char>(streamBuff)), istreambuf_iterator<char>());
	streamBuff.close();

	return buffer;
}

/**
 * Helper function to write data in a file
 * @param filename: the path to be written at
 * @param data: the data to be written
 */
void writeToFile(const string& filename, const string& data)
{
	BIO* bio = BIO_new_file(filename.c_str(), "w");
	BIO_printf(bio, "%s", data.c_str());

	BIO_free_all(bio);
}

/**
 * Algorithm used to hash data using the desired hash function
 * @param type: the type of hash function
 * @param plainText: the text to be hashed
 * @param plainTextSize: the size of the text which will be hashed
 * @return a hashed string of the encrypted data or an empty string if an error occured
 */
string encrypt(const EVP_MD* type, const string& plainText, size_t plainTextSize)
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();

	if (!EVP_DigestInit(ctx, type))
	{
		cout<<"\nEVP_DigestInit failed\n";
		return string();
	}

	if (!EVP_DigestUpdate(ctx, plainText.c_str(), plainTextSize))
	{
		cout<<"\nEVP_DigestUpdate failed\n";
		return string();
	}

	auto bytesWritten = new unsigned int{};
	auto outData = new unsigned char[EVP_MAX_MD_SIZE]{};
	if(!EVP_DigestFinal(ctx, outData, bytesWritten))
	{
		cout<<"\nEVP_DigestFinal failed\n";
		return string();
	}

	return string(reinterpret_cast<const char*>(outData));
}

/**
 * Function to get the number of identical bytes in two strings
 * @param string1
 * @param string2
 * @return integer representing the number of identical bytes or -1 in case of an error
 */
int sameByteOccurences(const string& string1, const string& string2)
{
	int occurences = 0;
	if(string1.length() != string2.length())
	{
		cout<<"The string should have the same size";
		return -1;
	}

	printf("////// SAME BYTES ///////\n");
	for (size_t i = 0; i < string1.length(); i++)
	{
		for(size_t j = 0; j < string1.length(); j++)
		{
			if (string1[i] == string2[j])
			{
				printf("index %zu on first, index %zu on second: %hhx\n",i,j, string2[j]);
				occurences++;
			}
		}
	}
	printf("////// SAME BYTES ///////\n");
	return occurences;
}

int main()
{
	//read the texts from their files
	const string text1 = readFromFile(PLAIN_TEXT_FILE1);
	const string text2 = readFromFile(PLAIN_TEXT_FILE2);

	//encrypt the texts using SHA256
	const string sha256EncryptedText1 = encrypt(EVP_sha256(), text1 ,text1.length());
	const string sha256EncryptedText2 = encrypt(EVP_sha256(), text2 ,text2.length());

	//write the texts to the defined files
	writeToFile(HASH1_SHA256_FILE, sha256EncryptedText1);
	writeToFile(HASH2_SHA256_FILE, sha256EncryptedText2);

	//encrypt the texts using MD5
	const string md5EncryptedText1 = encrypt(EVP_md5(), text1 ,text1.length());
	const string md5EncryptedText2 = encrypt(EVP_md5(), text2 ,text2.length());

	//write the texts to the defined files
	writeToFile(HASH1_MD5_FILE, md5EncryptedText1);
	writeToFile(HASH2_MD5_FILE, md5EncryptedText2);

	const string sha256HashedText1 = readFromFile(HASH1_SHA256_FILE);
	const string sha256HashedText2 = readFromFile(HASH2_SHA256_FILE);
	cout<<"Number of same bytes on SHA256 is: \n"<<sameByteOccurences(sha256EncryptedText1, sha256EncryptedText2)<<endl;

	const string md5HashedText1 = readFromFile(HASH1_MD5_FILE);
	const string md5HashedText2 = readFromFile(HASH2_MD5_FILE);
	cout<<"Number of same bytes on MD5 is: \n"<<sameByteOccurences(md5HashedText1, md5HashedText2)<<endl;
	return 0;
}