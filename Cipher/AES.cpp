#include "AES.h"
AlgorithmAES::AlgorithmAES(const string& filePath_in, const string& filePath_out, const string& Pass)
{
    this->filePath_in = filePath_in;
    this->filePath_out = filePath_out;
    this->psw = Pass;
}
AlgorithmAES::AlgorithmAES(const string& filePath_in, const string& filePath_out, const string& Pass, const string & iv)
{
    this->filePath_in = filePath_in;
    this->filePath_out = filePath_out;
    this->psw = Pass;
    this->filePath_Iv = iv;
}

void AlgorithmAES::encodeAES (AlgorithmAES enc)
{
    //Генерируем ключ
    SecByteBlock key(AES::MAX_KEYLENGTH);
	PKCS12_PBKDF<SHA256> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (CryptoPP::byte*)enc.psw.data(), enc.psw.size(), (CryptoPP::byte*)salt.data(), salt.size(), 1024, 0.0f);
    //Генерируем вектор инициализации(IV)
    AutoSeededRandomPool prng;
    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    //Записываем  вектор инициализации(IV) в файл (он понадобится при расшифровании)
    ofstream v_IV(string(enc.filePath_out + ".iv").c_str(), ios::out | ios::binary);
    v_IV.write((char*)iv, AES::BLOCKSIZE);
    v_IV.close();

    cout << "Файл \"IV\" c вектором инициализации успешно создан.\nПуть: " << enc.filePath_out << ".iv" << endl;

    //Шифрование. Результат в файл
    CBC_Mode<AES>::Encryption encr;
    encr.SetKeyWithIV(key, key.size(), iv);
    FileSource fs(enc.filePath_in.c_str(), true, new StreamTransformationFilter(encr, new FileSink(enc.filePath_out.c_str())));
    cout << "Шифрование прошло успешно.\nРезультат записан в файл, который находится по следующем пути:\n" << enc.filePath_out << endl;
}

void AlgorithmAES::decodeAES (AlgorithmAES dec)
{

    //Генерируем ключ (нужно использовать такой же пароль)
    SecByteBlock key(AES::MAX_KEYLENGTH); // Изменено
    PKCS12_PBKDF<SHA256> pbkdf; // Изменено
    pbkdf.DeriveKey(key.data(), key.size(), 0, (CryptoPP::byte*)dec.psw.data(), psw.size(), (CryptoPP::byte*)salt.data(), salt.size(), 1024, 0.0f);

    //Записываем вектор инициализации(IV) из файла, который формируется при шифровании
    byte iv[AES::BLOCKSIZE];
    ifstream v_IV(dec.filePath_Iv.c_str(), ios::in | ios::binary);
    //Проверки файла с вектором инициализации(IV) на ошибки
    if (v_IV.good()) {
        v_IV.read(reinterpret_cast<char*>(&iv), AES::BLOCKSIZE);
        v_IV.close();
    } else if (!v_IV.is_open()) {
        throw string ("Ошибка:: Файл \"IV\" (с вектором инициализации) не найден");
        v_IV.close();
    } else {
        throw string ("Ошибка:: Файл \"IV\" (с вектором инициализации) некорректный");
        v_IV.close();
    }
    //Расшифрование
    CBC_Mode<AES>::Decryption decr;
    decr.SetKeyWithIV(key, key.size(), iv);
    FileSource fs(dec.filePath_in.c_str(), true, new StreamTransformationFilter(decr, new FileSink(dec.filePath_out.c_str())));
    cout << "Расшифрование прошло успешно.\nРезультат записан в файл, который находится по следующем пути:\n" << dec.filePath_out << endl;
}
