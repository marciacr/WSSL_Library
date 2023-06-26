#include "src/libwssl_class.h"
#include <mosquitto.h>
#include <time.h>

#define destID "RCV1"
#define myMessage "MESSAGE PK01"

using namespace std;

/* ------------------ Evaluation Purporse Only ------------------ */
#define NUM_MSG 1
long int timeFirst, timeLast, sendTime; //DELAY CALC
long int eval_get_time_stamp();
void generate_delay_error(WsslSender *Sender, struct mosquitto *mosq, int i);
void generate_error_messages(WsslSender *Sender, struct mosquitto *mosq, int i);
/* ----------------------- Evaluation End ----------------------- */

/**
 * Function to publish messages using WSSL
 * */
void publish_messages(WsslSender *Sender, struct mosquitto *mosq)
{        
    Sender->sRet = Sender->init_wssl_snd(myMessage, Sender->label, destID, Sender->path, Sender->sRet);
    mosquitto_publish(mosq, NULL, "wssl", Sender->sRet.wsslMsg.length(), (const void*) Sender->sRet.wsslMsg.c_str(), 0, false);
}

void print_connection_table(WsslSender *Sender){
    // Print Sender table with all existing connections 
    cout << "  timeStamp(us) " << "   " << Sender->delimiter << "   " <<  "MESSAGE"   << "   " << Sender->delimiter << "   " <<  "Seq. Number" << endl;
    for(int i=0; i<Sender->sRet.table->size; i++){
        cout << Sender->sRet.table[i].timeStamp << "   " << Sender->delimiter << " ";
        cout << Sender->sRet.table[i].data << " " << Sender->delimiter << "     ";
        cout << Sender->sRet.table[i].seqNumber << endl << endl;
    }
}

int main()
{
    int rc;
    struct mosquitto *mosq;
    struct timespec remaining, request = {0, 100000};

    /**
     * Start the library instantiating the class
    */
    WsslSender Sender;                         // initialization by default constructor
    // WsslSender Sender2(Sender);                // initialization by copy constructor
    // WsslSender Sender3 = Sender2;               // Also initialization by copy constructor
    WsslSender Sender4("senderFile", "SND1");    // initialization by parametized constructor
    Sender = Sender4;                           // Assignment by copy assignment operator
    
    // Sender.get_my_public_key(Sender.path);                   // Get your own public key in Sender.key
    // std::cout << "\nkey: " << Sender.key << std::endl;
    // Sender.create_my_id("senderFile2", "senderLabel2");      // Create a new ID manually

    Sender.delimiter = "||";    //Define the delimiter if you want to change it, default is "||"

    mosquitto_lib_init();
    mosq = mosquitto_new("publisher-test", true, NULL);
    rc = mosquitto_connect(mosq, "192.168.1.162", 1885, 10);

    if (rc != 0)
    {
        cout << "Client could not connect to broker! Error Code: " << rc << endl;
        mosquitto_destroy(mosq);
        return -1;
    }
    // cout << "We are now connected to the broker!" <<endl;

    for (int i = 1; i <= NUM_MSG; i++)
    {
        /* ------------------ Evaluation Purporse Only ------------------ */
        if (i==1)
             timeFirst = eval_get_time_stamp();
        if (i==(NUM_MSG))
            timeLast = eval_get_time_stamp();
        /* ----------------------- Evaluation End ----------------------- */

        /**
         * Debug delete function of the table 
         **/
        // if (i == 9)
        //     usleep(11000000);
        
        /**
         * Remove comment of ONE of the three options to:
         * @publish_messages: publish a valid message, or
         * @generate_error_messages: purposely generate errors to change status of the message, or 
         * @generate_delay_error: puposely delay messages to detect delay above threshold
        */
        publish_messages(&Sender, mosq);
        // generate_error_messages(&Sender, mosq, i);
        // generate_delay_error(&Sender, mosq, i);

        /* ------------------ Evaluation Purporse Only ------------------ */
        /**
         * Evaluation of costs using ONLY MQTT
         * */
        // string testMsg = "0d56sd6sd59s0d90f9sd80f90sd9f80s9f80sefe89sf09se8f09es0f9sf0ef89se0f9es8f9s|MESSAGE PK01|10000"; 
        // mosquitto_publish(mosq, NULL, "test/wssl", testMsg.length(), (const void*) testMsg.c_str(), 0, false);
        /* ----------------------- Evaluation End ----------------------- */
        
        print_connection_table(&Sender);
        cout << Sender.sRet.wsslMsg << endl << endl;
        nanosleep(&request, &remaining);
        mosquitto_loop(mosq,-1,1);
    }

    /* ------------------ Evaluation Purporse Only ------------------ */
    sendTime = timeLast - timeFirst;
    cout << "Sending time for " << NUM_MSG << " message(s): " << sendTime << " ms" << endl;
    /* ----------------------- Evaluation End ----------------------- */
    
    mosquitto_disconnect(mosq);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
    return 0;
}

/* ----------------------------------------- Evaluation Purporse Only ------------------------------------------- */

/**
 * Function responsible for publishing messages with erros
*/
void generate_error_messages(WsslSender *Sender, struct mosquitto *mosq, int i)
{
    if(i == 2){
        Sender->sRet = Sender->init_wssl_snd("Sending a wrong signature", Sender->label, destID, Sender->path, Sender->sRet);
        Sender->sRet.wsslMsg.erase(8, 3); //Sabotage message byte 
        mosquitto_publish(mosq, NULL, "wssl", Sender->sRet.wsslMsg.length(), (const void*) Sender->sRet.wsslMsg.c_str(), 0, false);
    }else if (i == 4){
        Sender->sRet = Sender->init_wssl_snd("Sending a not existent Sender ID", "PK02", destID, Sender->path, Sender->sRet);      
        mosquitto_publish(mosq, NULL, "wssl", Sender->sRet.wsslMsg.length(), (const void*) Sender->sRet.wsslMsg.c_str(), 0, false);
    }else if (i == 6){
        usleep(15000);
        Sender->sRet = Sender->init_wssl_snd("MESSAGE OK", Sender->label, destID, Sender->path, Sender->sRet);        
        mosquitto_publish(mosq, NULL, "wssl", Sender->sRet.wsslMsg.length(), (const void*) Sender->sRet.wsslMsg.c_str(), 0, false);
    }else{
        Sender->sRet = Sender->init_wssl_snd("MESSAGE OK", Sender->label, destID, Sender->path, Sender->sRet);      
        mosquitto_publish(mosq, NULL, "wssl", Sender->sRet.wsslMsg.length(), (const void*) Sender->sRet.wsslMsg.c_str(), 0, false);
    }
}

/**
 * Function responsible for publishing messages with delays
 * */
void generate_delay_error(WsslSender *Sender, struct mosquitto *mosq, int i)
{
    if(i % 11 == 0){
        usleep(11000);
        Sender->sRet = Sender->init_wssl_snd("Generating a delayed message", Sender->label, destID, Sender->path, Sender->sRet);
        mosquitto_publish(mosq, NULL, "wssl", Sender->sRet.wsslMsg.length(), Sender->sRet.wsslMsg.c_str(), 0, false);
    }else{
        Sender->sRet = Sender->init_wssl_snd("MESSAGE OK", Sender->label, destID, Sender->path, Sender->sRet);       
        mosquitto_publish(mosq, NULL, "wssl", Sender->sRet.wsslMsg.length(), Sender->sRet.wsslMsg.c_str(), 0, false);
    }
}

long int eval_get_time_stamp()
{
    long int timeStamp = static_cast<long int>
        (chrono::duration_cast<chrono::milliseconds>(chrono::high_resolution_clock::now().time_since_epoch()).count());
 
    return timeStamp;
}
/* ----------------------------------------- Evaluation End ------------------------------------------- */
