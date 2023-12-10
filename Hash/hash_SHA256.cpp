#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
using namespace std;

string read_file(string way){
    ifstream file(way);
    string line;
    string entry;
    if (file.peek() == EOF){
        throw runtime_error("File is empty.");
    }
    while (getline(file, line)){
        entry += line;
    }
    file.close();
    return entry;
}

int main (){
    CryptoPP::SHA256 hash; // создание хэш-объекта

    cout <<"Algorithm: " << hash.AlgorithmName() << endl; // Имя алгоритма
    cout << "Diget size:" << hash.DigestSize() << endl; //размер хэша
    cout << "Block size:" << hash.BlockSize() << endl; // размер внутреннего Блока

    string path = "hash.txt"; // Путь до файла
    string FileContent;
    try {
        FileContent = read_file(path);
    } catch (const runtime_error& e) {
        cout << "Error: " << e.what() << endl;
        return 1;
    }

    cout << "File content: " << FileContent << endl; // содержимое файла

    vector<CryptoPP::byte> digest (hash.DigestSize());

    hash.Update(reinterpret_cast<const CryptoPP::byte*>(FileContent.data()),FileContent.size()); // формируем хэш
    hash.Final(digest.data()); // получаем хэш

    cout << "HASH in HEX format: ";
    CryptoPP::StringSource(digest.data(),digest.size(),true, new  CryptoPP::HexEncoder(new  CryptoPP::FileSink(cout))); // выводим хэш в формате "hex"
    cout << endl;
    return 0;
}
