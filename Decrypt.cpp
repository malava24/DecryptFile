#include <string>
#include <vector>
#include <fstream>
#include <exception>
#include <iostream>

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"
#include "../DecryptFile/PassGen.h"
#include <mutex>
#include <thread>

unsigned char key[EVP_MAX_KEY_LENGTH];
unsigned char iv[EVP_MAX_IV_LENGTH];

void ReadFile(const std::string& filePath, std::vector<unsigned char>& buf)
{
	std::basic_fstream<unsigned char> fileStream(filePath, std::ios::binary | std::fstream::in);
	if (!fileStream.is_open())
	{
		throw std::runtime_error("Can not open file " + filePath);
	}

	buf.clear();
	buf.insert(buf.begin(), std::istreambuf_iterator<unsigned char>(fileStream), std::istreambuf_iterator<unsigned char>());

	fileStream.close();
}

void WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf)
{
	std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary);
	fileStream.write(&buf[0], buf.size());
	fileStream.close();
}

void AppendToFile(const std::string& filePath, const std::vector<unsigned char>& buf)
{
	std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary | std::ios::app);
	fileStream.write(&buf[0], buf.size());
	fileStream.close();
}

void PasswordToKey(std::string& password)
{
	OpenSSL_add_all_digests();
	const EVP_MD* dgst = EVP_get_digestbyname("md5");
	if (!dgst)
	{
		throw std::runtime_error("no such digest");
	}

	const unsigned char* salt = NULL;
	if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
		reinterpret_cast<unsigned char*>(&password[0]),
		password.size(), 1, key, iv))
	{
		throw std::runtime_error("EVP_BytesToKey failed");
	}
}

void CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash)
{
	std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, &data[0], data.size());
	SHA256_Final(&hashTmp[0], &sha256);

	hash.swap(hashTmp);
}



bool DecryptAes(const std::vector<unsigned char> chipherText, std::vector<unsigned char>& plainText)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
	{
		return false;
	}

	std::vector<unsigned char> plainTextTextBuf(chipherText.size() + AES_DECRYPT);
	int plainTextSize = 0;

	if (!EVP_DecryptUpdate(ctx, &plainTextTextBuf[0], &plainTextSize, &chipherText[0], chipherText.size() - SHA256_DIGEST_LENGTH)) {
		EVP_CIPHER_CTX_free(ctx);
		return false;
	}

	int lastPartLen = 0;
	if (!EVP_DecryptFinal_ex(ctx, &plainTextTextBuf[0] + plainTextSize, &lastPartLen)) {
		EVP_CIPHER_CTX_free(ctx);
		return false;

	}
	plainTextSize += lastPartLen;
	plainTextTextBuf.erase(plainTextTextBuf.begin() + plainTextSize, plainTextTextBuf.end());

	plainText.swap(plainTextTextBuf);

	EVP_CIPHER_CTX_free(ctx);
	return true;
}

	std::vector<unsigned char> plainText;
	std::vector<unsigned char> chipherText;
	std::vector<unsigned char> hash;
void Decrypt()
{
	WriteFile("A:/1/DecryptFile/plain_text2", plainText);
}

void ReadChipherHash(std::vector<unsigned char>& chipherHash) {
		int a = 0;
	for (int i = chipherText.size() - 32; i < chipherText.size(); ++i) {
		chipherHash[a] = chipherText[i];
		++a;
	}
}

bool isHash(std::vector<unsigned char> chipherHash) {
	CalculateHash(plainText, hash);
	if (hash == chipherHash) {
		return true;
	}
	return false;
}


bool CheckPassword(std::string& password, std::vector<unsigned char> chipherHash) {
	PasswordToKey(password);
	if (DecryptAes(chipherText, plainText)) {
		if (isHash(chipherHash)) {
			Decrypt();
			return true;
		}
		return false;
	}
		return false;

	


}


int main()
{
	 

	 
	std::vector<unsigned char> chipherHash(32);
	ReadFile("A:/1/DecryptFile/chipher_text_brute_force", chipherText);
	ReadChipherHash(chipherHash);

	 
	std::vector<std::string> passwords;
	PassGen passwordsGen;
	
	 
	 
	try
	{
		for (;;) {
			passwords.clear();
			if (passwordsGen.GetPasswordsBatch(passwords)) {

				for (size_t i = 0; i < passwords.size(); ++i) {
					std::cout << passwords[i] << std::endl;
					if (CheckPassword(passwords[i], chipherHash)) {
						std::cout << "your pass = " << passwords[i] << std::endl;
						return 0;
					}

				}
			}
			else {
				std::cout << "not such passwords";
					return 0;
			}
		}

	}
	catch (const std::runtime_error& ex)
	{
		std::cerr << ex.what();
	}
}