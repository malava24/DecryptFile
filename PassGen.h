#pragma once
#include <vector>
#include <iostream>
 

class PassGen {
public:

	
	bool GetPasswordsBatch(std::vector<std::string>& passwords );


private:
	bool isZero();
private:
	std::string m_symbolsForPass = "0123456789abcdefghijklmnopqrstuvwxyz";
	int m_passwordLength = 1;
	int m_j = 0;
	std::vector<int> m_sate;
	const size_t m_passwordsCount = 10000;
	 
	
};