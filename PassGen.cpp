#include "PassGen.h"

void PassGen::ExportPassToFile(){

    int passLenght = 4;
    int numOfPasswords = 100000;
    const char* filename = "A:/wordlist.txt";

    std::ofstream outFile(filename);

    for (int k = 0; k < numOfPasswords; k++) {
        for (int i = 0; i < passLenght; ++i) {
            numOfChars(passLenght);
            passGenerator(passLenght);
            outFile << m_password[i];
        }
        outFile << std::endl;
    }
    outFile.close();
}

void PassGen::PassGenerator(int passLenght){

    m_password = new char[passLenght];

    for (int i = 0; i < m_numOfNumbers; ++i) {
        m_password[i] = char(rand() % 10 + 48);
    }
    for (int i = m_numOfNumbers; i < passLenght; ++i) {
        m_password[i] = char(rand() % 26 + 97);
    }
    std::random_shuffle(m_password, m_password + passLenght);
}

void PassGen::NumOfChars(int passLenght){

    m_numOfSmallChars = rand() % passLenght;
    int charRandEnd = passLenght - m_numOfSmallChars;
    m_numOfNumbers = passLenght - m_numOfSmallChars;
}
