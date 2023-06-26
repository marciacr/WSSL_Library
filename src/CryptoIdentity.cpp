#include "CryptoIdentity.h"


#include <sodium.h>
#include <sodium/crypto_sign.h>
#include <sys/stat.h>
#include <filesystem>
// #include <experimental/filesystem>
#include <stdexcept>
#include <fstream>
#include <random>
#include <iostream>
#include <cstring>

CryptoIdentity::CryptoIdentity(std::string path, std::string label) {
	if (sodium_init() == -1) {
		throw std::runtime_error("LibSodium could not be initialized");
	}
	sk = (unsigned char*) malloc(crypto_sign_SECRETKEYBYTES);
	pk = (unsigned char*) malloc(crypto_sign_PUBLICKEYBYTES);
	storedPath = path;
	id = getRand();
	this->label = label;

	if (crypto_sign_keypair(pk, sk) != 0){
		throw std::runtime_error("Crypto keys could not be generated");
	}
}

CryptoIdentity::CryptoIdentity(std::string path, bool genKeys){
	if (sodium_init() == -1) {
		throw std::runtime_error("LibSodium could not be initialized");
	}
	sk = (unsigned char*) malloc(crypto_sign_SECRETKEYBYTES);
	pk = (unsigned char*) malloc(crypto_sign_PUBLICKEYBYTES);
	storedPath = path;
}

CryptoIdentity::~CryptoIdentity() {
	free((void *) sk);
	free((void *) pk);
}

int CryptoIdentity::sign(const unsigned char *message, int mlen, unsigned char *signedMessage) {
	unsigned long long int resSize = 0;
	crypto_sign(signedMessage, &resSize, message, (unsigned long long int) mlen, this->sk);
	return (int) resSize;
}

std::string CryptoIdentity::sign(std::string message, int mlen){
	int signedSized = CryptoIdentity::SIGN_SIZE + message.length();
	unsigned char* messageSigned = (unsigned char*) malloc(signedSized * sizeof(char));
	int res = sign((const unsigned char *) message.c_str(), message.length(), messageSigned);
	std::string strRes((char*) messageSigned, signedSized);
	free(messageSigned);
	if(res >= 0)
		return strRes;
	else{
		strRes = "error";
		return strRes;	
	}
			
}

int CryptoIdentity::verifySignature(const unsigned char* signedMessage, int mlen, unsigned char* cleanMessage, int* cmlen, std::string key) {
	auto* bin = (unsigned char*) malloc(crypto_sign_PUBLICKEYBYTES);
	CryptoIdentity::hex2bin(key, bin, true);
	auto res = crypto_sign_open(cleanMessage, (unsigned long long int*)cmlen, signedMessage, mlen, bin);
	free(bin);
	return res;
}

std::string CryptoIdentity::verifySignature(std::string signedMessage, std::string key){
	int cleanSize = signedMessage.length() - CryptoIdentity::SIGN_SIZE;
	unsigned char* messageCleaned = (unsigned char*) malloc(cleanSize * sizeof(char));
	int res = verifySignature((const unsigned char *) signedMessage.c_str(), signedMessage.length(), messageCleaned, &cleanSize, key);
	std::string strRes((char*) messageCleaned, cleanSize);
	free(messageCleaned);
	if(res >= 0)
		return strRes;
	else{
		strRes = "error";
		return strRes;	
	}

		
}

void ReplaceStringInPlace(std::string& subject, const std::string& search, const std::string& replace) {
	size_t pos = 0;
	while ((pos = subject.find(search, pos)) != std::string::npos) {
		subject.replace(pos, search.length(), replace);
		pos += replace.length();
	}
}

void CryptoIdentity::addKnownIdentity(std::string label, const unsigned char *key) {
	ReplaceStringInPlace(label, std::string("\n"), std::string("_"));
	this->knownIdentities.emplace(label, CryptoIdentity::bin2hex((unsigned char *)key, true));
}

bool CryptoIdentity::save() {
	struct stat info{};
	int dirExists = stat(storedPath.c_str(), &info );
	if(dirExists != 0 ){
		// bool dirCreated = std::experimental::filesystem::create_directories(storedPath);
		bool dirCreated = std::filesystem::create_directories(storedPath);
		if(!dirCreated)
			return false;
	}

	//TODO possible improvement: write this encrypted
	bool res = true;
	res |= writeKeyToFile(storedPath + "/sk", this->sk, false);
	res |= writeKeyToFile(storedPath + "/pk", this->pk, true);
	res |= writeMapToFile(storedPath + "/knownIdentities", this->knownIdentities);
	res |= writeStringToFile(storedPath + "/label", this->label);
	res |= writeStringToFile(storedPath + "/id", std::to_string(this->id));
	return res;
}

CryptoIdentity* CryptoIdentity::load(std::string path) {
	CryptoIdentity* ci = new CryptoIdentity(path, false);
	ci->readKeyFromFile(ci->storedPath + "/sk", ci->sk, false);
	ci->readKeyFromFile(ci->storedPath + "/pk", ci->pk, true);
	ci->knownIdentities = ci->readMapFromFile(ci->storedPath + "/knownIdentities");
	ci->label = ci->readStringFromFile(ci->storedPath + "/label");
	ci->id = std::stoll(ci->readStringFromFile(ci->storedPath + "/id"));
	return ci;
}

bool CryptoIdentity::writeKeyToFile(std::string path, unsigned char* key, bool pk){
	try{
		std::string hex = CryptoIdentity::bin2hex(key, pk);
		writeStringToFile(path, hex);
	}catch (...){
		printf("write key failed\n");
		return false;
	}

	return true;
}

bool CryptoIdentity::writeStringToFile(std::string path, std::string text){
	try{
		std::ofstream skFile;
		skFile.open(path, std::ios::out | std::ios::trunc);
		skFile.write(text.c_str(), text.length());
		skFile.close();
	}catch (...){
		printf("write known identities failed\n");
		return false;
	}

	return true;
}

bool CryptoIdentity::writeMapToFile(std::string path, std::map<std::string, std::string> map) {
	try{
		std::ofstream skFile;
		// std::experimental::filesystem::create_directories(path);
		std::filesystem::create_directories(path);

		for(auto& kv : map){
			writeStringToFile(path + "/" + kv.first, kv.second);
		}
	}catch (...){
		printf("write known identities failed\n");
		return false;
	}

	return true;
}

void CryptoIdentity::readKeyFromFile(std::string path, unsigned char* key, bool pk) {
	std::string keyString = readStringFromFile(path);
	CryptoIdentity::hex2bin(keyString, key, pk);
}

std::string CryptoIdentity::readStringFromFile(std::string path){
	std::string res;

	try{
		std::ifstream skFile;
		skFile.open(path, std::ios::in);
		std::getline(skFile, res);
		skFile.close();
	}catch (...){
		printf("read string failed\n");
	}

	return res;
}

std::map<std::string, std::string> CryptoIdentity::readMapFromFile(std::string path) {
	std::map<std::string, std::string> map;
	try{
		// for (const auto & entry : std::experimental::filesystem::directory_iterator(path)){
		for (const auto & entry : std::filesystem::directory_iterator(path)){
			std::string key = readStringFromFile(entry.path().string());
			map.emplace(entry.path().filename().string(), key);
		}
	}catch (...){
		printf("read known identities failed\n");
	}

	return map;
}

unsigned CryptoIdentity::getRand(){
	std::random_device rd;
    std::mt19937 mt(rd());
    std::uniform_real_distribution<double> dist(0, 9223372036854775807.0); //MAX_INT

    return (unsigned) dist(mt);
}

std::vector<std::string>* CryptoIdentity::listKnownIdentities() {
	auto* labels = new std::vector<std::string>();
	for(auto& kv : this->knownIdentities){
		labels->push_back(kv.first);
	}
	return labels;
}

std::string CryptoIdentity::bin2hex(unsigned char *bin, bool pk) {
	int KEY_SIZE_CHAR = 0;
	if(pk)
		KEY_SIZE_CHAR = crypto_sign_PUBLICKEYBYTES;
	else
		KEY_SIZE_CHAR = crypto_sign_SECRETKEYBYTES;

	int hex_size = KEY_SIZE_CHAR * 2 + 1;
	char hex[hex_size];
	sodium_bin2hex(hex, hex_size, bin, KEY_SIZE_CHAR);
	return std::string(hex);
}

void CryptoIdentity::hex2bin(std::string hex, unsigned char* bin, bool pk) {
	int KEY_SIZE_CHAR = 0;
	if(pk)
		KEY_SIZE_CHAR = crypto_sign_PUBLICKEYBYTES;
	else
		KEY_SIZE_CHAR = crypto_sign_SECRETKEYBYTES;
	sodium_hex2bin(bin, KEY_SIZE_CHAR, hex.c_str(), KEY_SIZE_CHAR * 2 + 1, nullptr,
				   nullptr, nullptr);
}

std::string CryptoIdentity::getKnownKey(std::string label) {
	// if(this->knownIdentities.contains(label)) //Use this line if c++ version > 17
	// if(this->knownIdentities.find(label) != this->knownIdentities.end())
	if(this->knownIdentities.count(label) > 0)
		return this->knownIdentities.at(label);
	else{
		std::cout << "Get known keys failed " << std::endl;
		return "error";
	}
		
}
