#include "Decryptor.h"
 

Decryptor::Decryptor(const std::vector<unsigned char> chipherText) :
	m_chipherText(chipherText)
{
	ReadChipherHash(m_chipherHash, m_chipherText);
}

 bool Decryptor::CheckPassword(std::string& password) {
	PasswordToKey(password);
	std::vector<unsigned char> tmpPlainText;
	std::vector<unsigned char> tmpHash;

	if (DecryptAes(m_chipherText, tmpPlainText)) {
		if (isHash(m_chipherHash, tmpPlainText, tmpHash)) {
			WriteToFileDecryptedData(tmpPlainText);
			return true;
		}
		return false;
	}
	return false;

}

 bool Decryptor::isHash(std::vector<unsigned char> chipherHash, std::vector<unsigned char> tmpPlainText, std::vector<unsigned char> tmpHash) {
	 CalculateHash(tmpPlainText, tmpHash);
	 if (tmpHash == chipherHash) {
		 return true;
	 }
	 return false;
 }

 bool Decryptor::DecryptAes(const std::vector<unsigned char> chipherText, std::vector<unsigned char>& tmpPlainText)
 {
	 EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	 if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, m_key, m_iv))
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

 void Decryptor::PasswordToKey(std::string& password)
 {

	 const EVP_MD* dgst = EVP_get_digestbyname("md5");
	 if (!dgst)
	 {
		 throw std::runtime_error("no such digest");
	 }

	 const unsigned char* salt = NULL;
	 if (!EVP_BytesToKey(EVP_aes_128_cbc(), EVP_md5(), salt,
		 reinterpret_cast<unsigned char*>(&password[0]),
		 password.size(), 1, m_key, m_iv))
	 {
		 throw std::runtime_error("EVP_BytesToKey failed");
	 }
 }

 void Decryptor::CalculateHash(const std::vector<unsigned char>& data, std::vector<unsigned char>& hash)
 {
	 std::vector<unsigned char> hashTmp(SHA256_DIGEST_LENGTH);

	 SHA256_CTX sha256;
	 SHA256_Init(&sha256);
	 SHA256_Update(&sha256, &data[0], data.size());
	 SHA256_Final(&hashTmp[0], &sha256);

	 hash.swap(hashTmp);
 }

 void Decryptor::WriteToFileDecryptedData(std::vector<unsigned char>& tmpPlainText)
 {
	 WriteFile("A:/1/DecryptFile/plain_text2", tmpPlainText);
 }

 void Decryptor::WriteFile(const std::string& filePath, const std::vector<unsigned char>& buf)
 {
	 std::basic_ofstream<unsigned char> fileStream(filePath, std::ios::binary);
	 fileStream.write(&buf[0], buf.size());
	 fileStream.close();
 }

 void Decryptor::ReadChipherHash(std::vector<unsigned char>& chipherHash, std::vector<unsigned char>& chipherText) {
	 for (size_t i = chipherText.size() - 32; i < chipherText.size(); ++i) {
		 chipherHash.push_back(chipherText[i]);
	 }
 }

