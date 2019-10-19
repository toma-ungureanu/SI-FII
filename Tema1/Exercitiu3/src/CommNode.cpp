#include <cstring>
#include "CommNode.h"

AESKey *CommNode::getKey() const
{
	return m_key;
}

void CommNode::setKey(AESKey *key)
{
	m_key = key;
}

const unsigned char* CommNode::getMessage() const
{
	return m_message;
}

void CommNode::setMessage(unsigned char* message)
{
	if(strcmp(reinterpret_cast<const char *>(message), "ecb") == 0)
	{
		m_opMode = "ecb";
	}
	else if(strcmp(reinterpret_cast<const char *>(message), "cbc") == 0)
	{
		m_opMode = "cbc";
	}
	m_message = message;
}

const string &CommNode::getOpMode() const
{
	return m_opMode;
}

void CommNode::setOpMode(const string &opMode)
{
	m_opMode = opMode;
}

AESKey *CommNode::getProvKey() const
{
	return m_provKey;
}

void CommNode::setProvKey(AESKey *provKey)
{
	m_provKey = provKey;
}
