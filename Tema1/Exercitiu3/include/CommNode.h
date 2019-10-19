#ifndef SITEMA1_COMMNODE_H
#define SITEMA1_COMMNODE_H

#include <string>
#include <AESKey.h>

using namespace std;
/**
 * Communication node to simulate the real communication between two entities
 */
class CommNode
{
private:
	/**
	 * The key which will encrypt/decrypt the message with
	 */
	AESKey* m_key{};
	/**
	 * The provisioned key which will be used when we start the communication
	 */
	AESKey* m_provKey{};
	unsigned char* m_message{};
	string m_opMode;

public:
	explicit CommNode(AESKey* key) : m_key(key){m_message = new unsigned char[256];};
	CommNode() = default;

	[[nodiscard]] const unsigned char* getMessage() const;
	[[nodiscard]] const string &getOpMode() const;
	[[nodiscard]] AESKey *getProvKey() const;
	[[nodiscard]] AESKey *getKey() const;

	void setMessage(unsigned char* message);
	void setOpMode(const string &opMode);
	void setProvKey(AESKey *provKey);
	void setKey(AESKey *key);
};


#endif //SITEMA1_COMMNODE_H
