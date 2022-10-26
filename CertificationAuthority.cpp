#include <iostream>
#include <sys/stat.h>

#include "CryptoIdentity.h"


CryptoIdentity* getIdentity();

int main(){

	CryptoIdentity* certAuth = getIdentity();

	char option = '\0';

	const char exit = 'e';
	const char create = 'c';
	const char list = 'l';
	const char helpchar = 'h';
	const std::string help = "/**\n"
							 " * Options:\n"
							 " * c: create\n"
							 " * l: list\n"
							 " * e: exit\n"
							 " */";

	/**
	 * Options:
	 * c: create
	 * l: list
	 * e: exit
	 */
	 while(option != exit){
		 std::cout << std::endl;
		 std::cout << help << std::endl;
		 std::cin >> option;
		 switch (option) {
			 case exit:
				 break;

			 case create:
			 {
				 std::string label, path;
				 std::cout << "Please enter path to store the credentials:" << std::endl;
				 std::cin >> path;
				 std::cout << "Please enter credentials' label:" << std::endl;
				 std::cin >> label;
				 CryptoIdentity temp(path, label);
				 temp.save();
				 certAuth->addKnownIdentity(label, temp.pk);
				 break;
			 }

			 case list:
				 std::cout << "Known identities:" << std::endl;
				 for(const std::string& label : *certAuth->listKnownIdentities()){
					 std::cout << label << std::endl;
				 }
				 break;

			 case helpchar:
				 std::cout << help << std::endl;
				 break;

			 default:
				 std::cout << "Unrecognized option." << std::endl;
				 std::cout << help << std::endl;
		 }
	 }

	 delete certAuth;
}

CryptoIdentity* getIdentity() {
	struct stat buffer{};
	std::string path = "./CA";
	std::string label = "CA";
	CryptoIdentity* res = nullptr;

	bool exists = (stat (path.c_str(), &buffer) == 0);
	if (exists){
		res = CryptoIdentity::load(path);
	} else {
		res =  new CryptoIdentity(path, label);
	}
	return res;
}
