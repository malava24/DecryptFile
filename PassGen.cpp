#include "PassGen.h"
 
	bool PassGen::isZero() {
		for (size_t i = 0; i < m_sate.size(); ++i){
			if(m_sate[i] != 0){
				return false;
			}
		}
		return true;
}

bool PassGen::GetPasswordsBatch(std::vector<std::string>& passwords) {
	if (m_passwordLength == 5) {
		return false;
	}
	std::string tmp;
 
	for (; m_passwordLength < 5; ++m_passwordLength) {

		if (isZero()) {
			m_sate.assign(m_passwordLength + 1, 0);
		}
		for (;;)
		{

			if (passwords.size() == m_passwordsCount) {
				return true;
			}
			for (unsigned int i = 1; i < m_sate.size(); ++i) {
				tmp.push_back(m_symbolsForPass[m_sate[i]]);
			}
			passwords.push_back(tmp);
			tmp.clear();

			for (m_j = m_passwordLength; m_sate[m_j] == (m_j ? 35 : 1); --m_j) {
				m_sate[m_j] = 0;
			}
			if (m_j == 0) break;
			m_sate[m_j]++;
		}
	}
	return true;
}




