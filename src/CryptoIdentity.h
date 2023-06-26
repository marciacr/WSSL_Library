#ifndef CRYPTOLIB_CRYPTOIDENTITY_H
#define CRYPTOLIB_CRYPTOIDENTITY_H

#include <map>
#include <string>
#include <vector>
#include <sodium/crypto_box.h>
#include <sodium/crypto_sign.h>

class CryptoIdentity {
public:
	// static const unsigned int SIGN_SIZE = crypto_sign_SEEDBYTES;
	static const unsigned int SIGN_SIZE = crypto_sign_BYTES;

	/**
	 * Creates an identity with public and private keys, used to sign messages
	 * @param path Where this identity will be stored
	 * @param label A string for easy identification of the identity (e.g., a process, a truck with serial number X)
	 */
	CryptoIdentity(std::string path, std::string label);

	/**
	 * Loads a previously stored identity
	 * @param path The path where the identity was saved
	 * @return The loaded CryptoIdentity
	 */
	static CryptoIdentity* load(std::string path);

	/**
	 * Stores the identity to disk
	 * @return If the operation was successful
	 */
	bool save();

	/**
	 * This identity signs a given string. The signature is prepended to the message.
	 * @param message The string to sign
	 * @param mlen The length of the message
	 * @param signedMessage A pointer where the signed message will be stored. It must have at least mlen + SIGN_SIZE bytes
	 * @return 0 if the signing was successful, -1 otherwise
	 */
	int sign(const unsigned char* message, int mlen, unsigned char* signedMessage);

	/**
	 * This identity signs a given string. The signature is prepended to the message.
	 * @param message The string to sign
	 * @param mlen The length of the message
	 * @return The signed message, NULL otherwise
	 */
	std::string sign(std::string message, int mlen);

	/**
	 * Verifies if a message was signed by a key.
	 * @param signedMessage The message to verify. The signature has to have been prepended, as per the sign method
	 * @param mlen The size of the signed message
	 * @param cleanMessage A pointer where to store the message without the signature. It must have at least mlen - SIGN_SIZE bytes
	 * @param cmlen A pointer where the method will store the clean message size; this pointer MUST be initialised to NULL or nullptr
	 * @param key The key required to verify the signature
	 * @return 0 if the signature matches the key, -1 otherwise
	 */
	int verifySignature(const unsigned char* signedMessage, int mlen, unsigned char* cleanMessage, int* cmlen, std::string key);

	/**
	 * Verifies if a message was signed by a key.
	 * @param signedMessage The message to verify. The signature has to have been prepended, as per the sign method
	 * @param mlen The size of the signed message
	 * @param cleanMessage A pointer where to store the message without the signature. It must have at least mlen - SIGN_SIZE bytes
	 * @param cmlen A pointer where the method will store the clean message size; this pointer MUST be initialised to NULL or nullptr
	 * @param key The key required to verify the signature
	 * @return 0 if the signature matches the key, -1 otherwise
	 */
	std::string verifySignature(std::string signedMessage, std::string key);

	/**
	 * Saves an identity of another process, i.e., another CryptoIdentity's public key. Includes a tag for easy retrieval. Overwrites if the label already exists
	 * @param label The "name" of the public key's owner
	 * @param key The key of the process
	 */
	void addKnownIdentity(std::string label, const unsigned char* key);

	/**
	 * Retrieves the public key of a previously saved identity.
	 * @param label The label of the identity
	 * @return A public key if the label has been previously stored, otherwise nullptr
	 */
	std::string getKnownKey(std::string label);

	/**
	 * Converts a binary key to a hexadecimal representation
	 * @param bin The string to convert
	 * @param pk True if it is a public key, false if it is a private key
	 * @return A string with the hexadecimal representation of the key
	 */
	static std::string bin2hex(unsigned char* bin, bool pk);

	/**
	 * Converts a hexadecimal representation of a key to binary
	 * @param hex The hexadecimal representation of the key
	 * @param bin A pointer to where the binary representation will be stored. Must be previously allocated
	 * @param pk True if it is a public key, false if it is a private key
	 */
	void hex2bin(std::string hex, unsigned char* bin, bool pk);

	/**
	 * @return A list of the identities known to this identity
	 */
	std::vector<std::string>* listKnownIdentities();
	~CryptoIdentity();
	
	/**
	 * The public key
	 */
	unsigned char* pk;
	
private:
	CryptoIdentity(std::string path, bool genKeys);

	bool writeKeyToFile(std::string path, unsigned char* key, bool pk);
	bool writeMapToFile(std::string path, std::map<std::string, std::string> map);
	bool writeStringToFile(std::string path, std::string text);
	void readKeyFromFile(std::string path, unsigned char* key, bool pk);
	std::map<std::string, std::string> readMapFromFile(std::string path);
	std::string readStringFromFile(std::string path);
	unsigned getRand();

	/**
	 * This is publicly accessible for test purposes only. Please do not use.
	 */
	unsigned char* sk;
	
	/**
	 * This is publicly accessible for test purposes only. Please do not use.
	 */
	std::map<std::string, std::string> knownIdentities;
	/**
	 * This is publicly accessible for test purposes only. Please do not use.
	 */
	unsigned int id;
	/**
	 * This is publicly accessible for test purposes only. Please do not use.
	 */
	std::string storedPath;
	/**
	 * This is publicly accessible for test purposes only. Please do not use.
	 */
	std::string label;

};


#endif //CRYPTOLIB_CRYPTOIDENTITY_H
