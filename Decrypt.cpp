#include <string>
#include <vector>
#include <fstream>
#include <exception>
#include <iostream>
#include <conio.h>

#include "openssl/evp.h"
#include <openssl/aes.h>
#include "openssl/sha.h"
#include "PassGen.h"
#include <mutex>
#include <thread>
#include <chrono>
#include <Windows.h>
#include "Decryptor.h"


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


std::recursive_mutex g_mutex;
PassGen g_passwordsGen;
bool g_isPassFound = false;
int g_numOfVerifiedPass = 0;
std::vector<std::string> g_verifiedPasswords;
void GenPasswords(bool isWritePassToFile, const std::vector<unsigned char>& chipherText) {
	std::vector<std::string> passwords;
	Decryptor decryptor(chipherText);
	
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
			if (isWritePassToFile) {
				g_mutex.lock();
				g_verifiedPasswords.push_back(passwords[i]);
				g_mutex.unlock();
			}	
		}		
	}
}
 
 
void ProgressVerifiedPass() {
	// number of four-digit password combinations
	const int maxNum = 1679616;
	double oneProccent = 16796.16;
	double curNum = 0;
	double progress = 0;

	while (!g_isPassFound)
	{
		if (progress > 100) {
			throw std::exception("Password isn't found");
		}
		if (g_numOfVerifiedPass >= curNum) {
			++progress;
			curNum += oneProccent;
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

		std::vector<unsigned char> chipherText;
		ReadFile("../DecryptFile/chipher_text_brute_force", chipherText);
		 

		std::cout << "Do you know a password? - y/n" << std::endl;
		std::string firstAnswer;
		std::cin >> firstAnswer;


		if (firstAnswer == "y") {
			std::cout << "Enter the password" << std::endl;
			std::string pass;
			std::cin >> pass;
 
			Decryptor decryptor(chipherText);
		    std::vector<unsigned char> chipherHash(32);
			decryptor.ReadChipherHash(chipherHash, chipherText);

			if (decryptor.CheckPassword(pass)) {
				std::cout << "file successfully encrypted with password  :) - " << pass << std::endl;
			}
			else {
				std::cerr << "smth wrong" << std::endl;
			}
 
		}
		else if (firstAnswer == "n") {
			std::cout << "Do you want to save verified passwords in logPass.txt ?" << std::endl << std::endl;
			std::cout << "Enter 'y' to continue saving verified passwords" << std::endl << "Enter any key to continue without saving" << std::endl << std::endl;
			std::string secAnswer;
			std::cin >> secAnswer;
			bool isWritePassToFile = false;

			if (secAnswer == "y") {
				isWritePassToFile = true;
			}
			auto start = std::chrono::high_resolution_clock::now();

			std::thread gPass1(GenPasswords, isWritePassToFile, std::ref(chipherText));
			std::thread gPass2(GenPasswords, isWritePassToFile, std::ref(chipherText));
			std::thread gPass3(GenPasswords, isWritePassToFile, std::ref(chipherText));
			std::thread progress(ProgressVerifiedPass);
			
			progress.join();
			gPass1.join();
			gPass2.join();
			gPass3.join();

			auto end = std::chrono::high_resolution_clock::now();
			std::chrono::duration<float> duration = end - start;
			std::cout << std::endl;
			std::cout << "Time elapsed:  " << duration.count() << " sec." << std::endl;

			if (isWritePassToFile) {
				std::ofstream  logPass("../DecryptFile/logPass.txt");
				for (size_t i = 0; i < g_verifiedPasswords.size(); ++i) {
					logPass << g_verifiedPasswords[i] << "\n";
				}	
			}
			 

		}
		else {
			std::cerr << "Wrong answer, try again";
		}

	}
	catch (const std::runtime_error& ex)
	{
		std::cerr << ex.what();
	}
} 