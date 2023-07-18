#include "CryptoIdentity.h"   // VORTEX Library for digital signatures
#include <fstream>
#include <iostream>
#include <chrono>             // Chrono library is used to deal with date and time.
#include <cstring>             // string from C
#include <unistd.h>           // sleep()
#include <sys/stat.h>
#include <stdexcept>

#define SIZE_TABLE 500
#define SIZE_MSG 3
#define INTER_MSG_DELAY_MAX 10000
#define SENT_RCV_DELAY_MAX 20000
#define LIM_TIME_SEC 2

#define EMPTY_TABLE 0
#define OK 1
#define REPLACE_MSG 2
#define NEW_MSG 3

/**
 * PacketSnd represents the structure of the table inside the Sender 
 * @var seqNumber Sequence number of the message to be sent
 * @var size Size of the table/ number of connections
 * @var timeStamp Time Stamp of the message to be sent
 * @var data The string data containing the WSSL message
 * @var senderID The string containing the ID of the Receiver (destination)
 */
struct PacketSnd
{
    int seqNumber;
    int size;
    long int timeStamp;
    std::string data;
    std::string destID;
};

/**
 * SenderReturn represents the returns from WSSL_Sender 
 * @var table Pointer to a matrix of arrays, contains all the Sender connections
 * @var wsslMsg String containing the WSSL message
 */
class SenderReturn
{
public:
    struct PacketSnd *table;
    std::string wsslMsg;
};

/**
 * PacketRcv represents the structure of the table inside the Receiver 
 * @var status Message Status: OK: 0, DUPLICATED: 1, OUT-OF-ORDER: 2, LOST: 3, INTER-MESSAGE DELAY: 4,  DELAY SENT-RECEIVED: 5
 * @var seqNumber Sequence number of the message received
 * @var size Size of the table/ number of connections
 * @var delaySnd Inter-message delay 
 * @var delayRcv Delay between the sent time and the received time
 * @var timeStamp Time Stamp of the message received
 * @var data The string data containing the plain message
 * @var senderID The string containing the ID of the Sender
 */

struct PacketRcv
{
    int status;   
    int seqNumber; 
    int size;          
    long int delaySnd;  
    long int delayRcv; 
    long int timeStamp;
    std::string data;
    std::string senderID;
};

/**
 * ReceiverReturn represents the returns from WSSL_Receiver
 * @var table Pointer to a matrix of arrays, contains all the Received connections
 * @var wsslMsg String containing the WSSL message
 */
class ReceiverReturn //: public PacketRcv
{
public:
    struct PacketRcv *table;
    std::string plainText;
};

/**
 * LibWssl represents the WSSL general functionalities 
 * @var sizeLabel Set number of digits of the identities label, uses four digits as a default (e.g. SND1)
 * @private cryptoID Pointer to create and load the security identity
 */
class LibWssl
{
private:

    /**
     * Responsible to delete connexions older then @def LIM_TIME_SEC inside the WSSL Sender
     * @param sRet SenderReturn object
    */
    void delete_old_connexions_snd(SenderReturn);

    /**
     * Responsible to delete connexions older then @def LIM_TIME_SEC inside the WSSL Receiver
     * @param rRet ReceiverReturn object
    */
    void delete_old_connexions_rcv(ReceiverReturn);

    
    CryptoIdentity *cryptoID;

public:    
    int sizeLabel = 4;
    std::string delimiter = "||";

    /**
     * Responsible for initialize the WSSL Sender
     * @param msg Message received from application
     * @param senderID Sender identificator, also called label
     * @param destID Destination identificator, also called label
     * @param path Path name of the Sender identity
     * @param timeStamp Time the message was sent in microseconds 
     * @param sRet SenderReturn object
     * @return Updated SenderReturn object (sRet)
     * */
    SenderReturn init_wssl_snd(std::string msg, std::string senderID, std::string destID, std::string path, SenderReturn sRet);

    /**
     * Responsible for initialize the WSSL Sender
     * @param wsslMsg Signed message received from Sender
     * @param path Path name of the Sender identity
     * @param sRet ReceiverReturn object
     * @return Updated ReceiverReturn object (rRet) if success, "error" otherwise
     * */
    ReceiverReturn init_wssl_rcv(std::string wsslMsg, std::string path, ReceiverReturn rRet);
  
    /**
     * Creates an identity with public and private keys, used to sign messages
     * @param path Where this identity will be stored
     * @param label A string for easy identification of the identity (e.g., a process, a truck with serial number X)
     */
    void create_my_id (std::string path, std::string label){
        cryptoID = new CryptoIdentity(path, label);
        cryptoID->save();
    }

    /**
     * Add an identity with its public key inside path /path/knownidentities, used to exchange public keys
     * @param path Where this identity will be added
     * @param label A string for easy identification of the identity you want to add
     * @param pk Pointer to the public key of the identity you want to add
     */
    void add_known_identity (std::string path, std::string label, const unsigned char *pk){
        cryptoID = CryptoIdentity::load(path);
        cryptoID->addKnownIdentity(label, pk);
        cryptoID->save();
    }

    /**
     * Get the caller public key
     * @param path Path name of the identity
     * @return Public key of the caller application
     */
    std::string get_my_public_key (std::string path){
        cryptoID = CryptoIdentity::load(path);
        //std::cout << "public key: " << cryptoID->pk << std::endl;
        std::string _pk = ((const char*)cryptoID->pk);
        return _pk;
    }

    /**
     * Function that calculates the current time (timeStamp) in microseconds using a high resolution clock, used to update message timestamps
     * @return Time stamp in microseconds
     */
    long int get_time_stamp_micro(){
        long int timeStamp = static_cast<long int>
            (std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now().time_since_epoch()).count());

        return timeStamp;
    }
};

/**
 * WSSL Sender class, an object of this class must be created by the application to proper use of WSSL Library
 * @var path Path name of the Sender identity
 * @var label Label name of the Sender identity
 * @var key Store public key of the Sender identity
 * @var sRet SenderReturn object type
*/
class WsslSender : public LibWssl{

private: 
    int newDir = 0;
    struct stat info{};

    /** 
     * Create new identity only if it still does not exist and stores public key inside variable key
     */ 
    void sender_init(std::string path, std::string label){
        newDir = stat(path.c_str(), &info );
        if(newDir){
            create_my_id(path, label);
        }
        key = get_my_public_key(path);
    }

public:
    SenderReturn sRet;
    std::string path, label, key;

    /* Copy constructor */
    WsslSender(const WsslSender &old) 
    {
        path = old.path;
        label = old.label;
        key = old.key;

        sRet.table = new PacketSnd[SIZE_TABLE];
        if(sRet.table == nullptr)
            throw std::runtime_error("Sender Table could not allocate memory");

        memcpy(sRet.table,old.sRet.table,sizeof(old.sRet.table) );
        // sRet.table = old.sRet.table;
    }

    /* Assignment operator */
    WsslSender & operator = (const WsslSender &other) 
    {
        if(this != &other){
            path = other.path;
            label = other.label;
            key = other.key;

            sRet.table = new PacketSnd[SIZE_TABLE];
            if(sRet.table == nullptr)
                throw std::runtime_error("Sender Table could not allocate memory");
            
            memcpy(sRet.table,other.sRet.table,sizeof(other.sRet.table));
        }
        return *this;
    }

    /* Default constructor / zero-argument constructor */
    WsslSender()    
    :   path ("Default_Sender"),
        label ("DF01")
    {
        sRet.table = new PacketSnd[SIZE_TABLE];

        if(sRet.table == nullptr)
            throw std::runtime_error("Sender Table could not allocate memory");
        
        sender_init(this->path, this->label);
    } 

    /* Parametized constructor */
    WsslSender(std::string path, std::string label)
    :   path (path),
        label (label)
    {    

        sRet.table = new PacketSnd[SIZE_TABLE];

        if(sRet.table == nullptr){
            throw std::runtime_error("Sender Table could not allocate memory");
        }
        sender_init(this->path, this->label);
    }

    /* Destructor */
    ~WsslSender() {
        if(sRet.table != nullptr){
            delete [] sRet.table;
            sRet.table = NULL;
        }

        path.clear();
        label.clear();
        key.clear();
    }
};

/**
 * WSSL Receiver class, an object of this class must be created by the application to proper use of WSSL Library
 * @var path Path name of the Receiver identity
 * @var label Label name of the Receiver identity
 * @var key Store public key of the Receiver identity
 * @var rRet ReceiverReturn object type
*/
class WsslReceiver : public LibWssl{

private: 
    int newDir = 0;
    struct stat info{};

    /** 
     * Create new identity only if it still does not exist and stores public key inside variable key
     */ 
    void receiver_init(std::string path, std::string label){
        newDir = stat(this->path.c_str(), &info );
        if(newDir){
            create_my_id(this->path, this->label);
        }
        this->key = get_my_public_key(this->path);
    }

public:
    std::string path, label, key;
    ReceiverReturn rRet;

    /* Copy constructor */
    WsslReceiver(const WsslReceiver &old)
    {
        path = old.path;
        label = old.label;
        key = old.key;

        // rRet.table = (PacketRcv *)malloc(sizeof(PacketRcv)*SIZE_TABLE);
        rRet.table = new PacketRcv[SIZE_TABLE];

        if(rRet.table == nullptr)
            throw std::runtime_error("Receiver Table could not allocate memory");

        memcpy(rRet.table,old.rRet.table,sizeof(old.rRet.table));


    }

    /* Assignment operator */
    WsslReceiver & operator = (const WsslReceiver &other)
    {
        if(this != &other){
            path = other.path;
            label = other.label;
            key = other.key;

            rRet.table = new PacketRcv[SIZE_TABLE];

            if(rRet.table == nullptr)
                throw std::runtime_error("Receiver Table could not allocate memory");
                
            memcpy(rRet.table,other.rRet.table,sizeof(other.rRet.table));
        }
        return *this;
    }

    /* Default constructor / zero-argument constructor */
    WsslReceiver ()
    :   path ("Default_Receiver"),
        label ("RCV1")
    {
        rRet.table = new PacketRcv[SIZE_TABLE];
        if(rRet.table == nullptr)
            throw std::runtime_error("Receiver Table could not allocate memory");
        
        receiver_init(this->path, this->label);
    } 

    /* Parametized constructor */
    WsslReceiver(std::string path, std::string label)
    :   path (path),
        label (label)
    {
        rRet.table = new PacketRcv[SIZE_TABLE];
        
        if(rRet.table == nullptr)
            throw std::runtime_error("Receiver Table could not allocate memory");

        receiver_init(this->path, this->label);
    }

    /* Destructor */
    ~WsslReceiver() {
        if(rRet.table != nullptr){
            delete [] rRet.table;
            rRet.table = NULL;
        }

        path.clear();
        label.clear();
        key.clear();
    }
};
