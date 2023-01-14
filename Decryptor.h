#pragma once
#include <iostream>
#include <vector>
#include <fstream>
#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"

class Decryptor {
public:
	
	Decryptor(const std::vector<unsigned char> chipherText);

	bool CheckPassword(std::string& password);

	bool isHash(std::vector<unsigned char> chipherHash, std::vector<unsigned char> tmpPlainText, std::vector<unsigned char> tmpHash);

	bool DecryptAes(const std::vector<unsigned char> chipherText, std::vector<unsigned char>& tmpPlainText);

	void PasswordToKey(std::string& password);

	void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash);

	void WriteToFileDecryptedData(std::vector<unsigned char>& tmpPlainText);

	void WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf);

	void ReadChipherHash(std::vector<unsigned char>& chipherHash, std::vector<unsigned char>& chipherText);

private:
	unsigned char m_key[EVP_MAX_KEY_LENGTH] = {0};
	unsigned char m_iv[EVP_MAX_IV_LENGTH] = {0};
	std::vector<unsigned char> m_chipherText;
	std::vector<unsigned char> m_chipherHash;
	
};