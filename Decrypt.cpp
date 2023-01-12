#include <string>
#include <vector>
#include <fstream>
#include <exception>
#include <iostream>

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"
#include "PassGen.h"
#include <mutex>
#include <thread>
#include <chrono>
#include <Windows.h>
#include "Decryptor.h"


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

/*void WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf)
{
	std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary);
	fileStream.write(&buf[0], buf.size());
	fileStream.close();
}

 

void PasswordToKey(std::string& password)
{

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



bool DecryptAes(const std::vector<unsigned char> chipherText, std::vector<unsigned char>& tmpPlainText)
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

	tmpPlainText.swap(plainTextTextBuf);


	EVP_CIPHER_CTX_free(ctx);
	return true;
}


void Decrypt(std::vector<unsigned char>& tmpPlainText)
{
	WriteFile("A:/1/DecryptFile/plain_text2", tmpPlainText);
}


void ReadChipherHash(std::vector<unsigned char>& chipherHash) {
	int a = 0;
	for (size_t i = g_chipherText.size() - 32; i < g_chipherText.size(); ++i) {
		chipherHash[a] = g_chipherText[i];
		++a;
	}
}

bool isHash(std::vector<unsigned char> chipherHash, std::vector<unsigned char> tmpPlainText, std::vector<unsigned char> tmpHash) {
	CalculateHash(tmpPlainText, tmpHash);
	if (tmpHash == chipherHash) {
		return true;
	}
	return false;
}


bool CheckPassword(std::string& password, std::vector<unsigned char> chipherHash) {
	PasswordToKey(password);
	std::vector<unsigned char> tmpPlainText;
	std::vector<unsigned char> tmpHash;

	if (DecryptAes(g_chipherText, tmpPlainText)) {
		if (isHash(chipherHash, tmpPlainText, tmpHash)) {
			Decrypt(tmpPlainText);
			return true;
		}
		return false;
	}
	return false;

}
	*/

std::vector<unsigned char> g_chipherText;
std::recursive_mutex g_mutex;
PassGen g_passwordsGen;
bool g_isPassFound = false;
int g_numOfVerifiedPass = 0;
bool g_isWritePassToFile = false;
std::vector<std::string> g_verifiedPasswords;
void GenPasswords(bool isWritePassToFile) {
	std::vector<std::string> passwords;
	Decryptor decryptor(g_chipherText);
	

	while (!g_isPassFound) {
		passwords.clear();

		g_mutex.lock();
		if (!g_isPassFound) {
			g_passwordsGen.GetPasswordsBatch(passwords);
		}
		g_mutex.unlock();

		for (size_t i = 0; i < passwords.size(); ++i) {
			g_mutex.lock();
			++g_numOfVerifiedPass;
			g_mutex.unlock();

			if (decryptor.CheckPassword(passwords[i])) {
				std::cout << std::endl << passwords[i] << "  -  your pass" << std::endl;
				g_isPassFound = true;
				break;
			}
			
		}
		g_mutex.lock();
		if (isWritePassToFile) {

			for (size_t i = 0; i < passwords.size(); ++i) {
				g_verifiedPasswords.push_back(passwords[i]);
			}
		}
		g_mutex.unlock();
	}
}
/*std::vector<unsigned char> a;
void Write() {
	for (size_t i = 0; i < g_verifiedPasswords.size(); ++i) {
		strcpy_s((char*)a[0], g_verifiedPasswords.size(), g_verifiedPasswords[i].c_str());
	}
}*/
 
void ProgressVerifiedPass() {
	// number of four-digit password combinations
	const int maxNum = 1679616;

	double oneProccent = 16796.16;
	double curProccentInNum = 0;
	double progress = 0;

	while (!g_isPassFound)
	{
		if (progress > 100) {
			throw std::exception("Password isn't found");
		}
		if (g_numOfVerifiedPass >= curProccentInNum) {
			++progress;
			curProccentInNum += oneProccent;
		}
		 
		std::cout << g_numOfVerifiedPass << " from " << maxNum << " passwords checked " << "[" << progress << "%]";
		 
		for (int i = 0; i < 20; ++i) {
			std::cout << "\b\b\b";
		}

	}
}

void DeleteCoursore() {
	void* handle = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_CURSOR_INFO structCursorInfo;
	GetConsoleCursorInfo(handle, &structCursorInfo);
	structCursorInfo.bVisible = FALSE;
	SetConsoleCursorInfo(handle, &structCursorInfo);
}

int main()
{
	try
	{
		
		DeleteCoursore();
		OpenSSL_add_all_digests();

		ReadFile("A:/1/DecryptFile/chipher_text_brute_force", g_chipherText);
		 

		std::cout << "Do you know a password? - y/n" << std::endl;
		std::string firstAnswer;
		std::cin >> firstAnswer;


		if (firstAnswer == "y") {
			std::cout << "Enter the password" << std::endl;
			std::string pass;
			std::cin >> pass;
 
			Decryptor decryptor(g_chipherText);
		    std::vector<unsigned char> chipherHash(32);
			decryptor.ReadChipherHash(chipherHash, g_chipherText);

			if (decryptor.CheckPassword(pass)) {
				std::cout << "file successfully encrypted with password  :) - " << pass << std::endl;
			}
			else {
				std::cerr << "smth wrong" << std::endl;
			}



		}
		else if (firstAnswer == "n") {
			std::cout << "Do you want to save verified passwords in logPass.txt ?" << std::endl << "Enter - y/n" << std::endl;
			std::string secAnswer;
			std::cin >> secAnswer;

			auto start = std::chrono::high_resolution_clock::now();

			if (secAnswer == "y") {
				g_isWritePassToFile = true;
				std::ofstream outfile("../DecryptFile/logPass.txt");

			}
			std::thread t1(GenPasswords, g_isWritePassToFile);
			std::thread t2(GenPasswords, g_isWritePassToFile);
			std::thread t3(GenPasswords, g_isWritePassToFile);
			std::thread t4(ProgressVerifiedPass);

			
			t4.join();
			t1.join();
			t2.join();
			t3.join();

		//	Write();
		//WriteFile("../DecryptFile/logPass.txt", a);

			auto end = std::chrono::high_resolution_clock::now();

			std::chrono::duration<float> duration = end - start;
			std::cout << std::endl;
			std::cout << "Time elapsed:  " << duration.count() << " sec." << std::endl;


		}

	}
	catch (const std::runtime_error& ex)
	{
		std::cerr << ex.what();
	}
} 