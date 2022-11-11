#pragma once

class PassGen {
public:
    void ExportPassToFile();
    void PassGenerator(int passLenght);
    void NumOfChars(int passLenght);

private:
    int m_numOfSmallChars;
    int m_numOfNumbers;
    char* m_password;
};