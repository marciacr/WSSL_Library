#include "src/lib_wssl.h"
#include <iostream>
#include <mosquitto.h>
#include <unistd.h>
#include <chrono> //used for testing purpose

#define receiverID "PK02"
#define myMessage "MY_MESSAGE"
#define NUM_MSG 20

using namespace std;

/* ------------------ Testing Purporse Only ------------------ */
long int time_first, time_last, send_time; //DELAY CALC
long int rget_timeStamp();
void generate_delayError(struct wssl_send_return sRet, struct mosquitto *mosq, int i);
void generate_errorMessages(struct wssl_send_return sRet, struct mosquitto *mosq, int i);

/* --------------- Function publishing messages --------------- */
void publish_messages(struct wssl_send_return sRet, struct mosquitto *mosq)
{
        const void *msg_mqtt;

        sRet = init_wssl_send("MESSAGE PK01", "PK01", receiverID, sRet);
        msg_mqtt = sRet.wssl_msg.c_str();        
        mosquitto_publish(mosq, NULL, "test/wssl", sRet.wssl_msg.length(), msg_mqtt, 0, false);

        // Remove comments bellow to publish a second message from a different sender
        // sRet = init_wssl_send("MESSAGE PK03", "PK03", receiverID, sRet);
        // msg_mqtt = sRet.wssl_msg.c_str();        
        // mosquitto_publish(mosq, NULL, "test/wssl", sRet.wssl_msg.length(), msg_mqtt, 0, false);

}

/* --------------- Main function initializes MQTT connection and calls WSSL library Sender --------------- */
int main()
{
    int rc, size_send;
    struct mosquitto *mosq;

    // Create sender struct and allocate memory 
    struct wssl_send_return sRet;
    sRet.table = (packet_send *)malloc(sizeof(packet_send)*500);

    if(sRet.table == NULL)
    {
        cout << "malloc failed!" << endl;   //could also call perror here
        free(sRet.table);
        sRet.table = NULL; 
    }

    mosquitto_lib_init();
    mosq = mosquitto_new("publisher-test", true, NULL);
    rc = mosquitto_connect(mosq, "localhost", 1883, 10);

    if (rc != 0)
    {
        cout << "Client could not connect to broker! Error Code: " << rc << endl;
        mosquitto_destroy(mosq);
        return -1;
    }
    cout << "We are now connected to the broker!" <<endl;
    mosquitto_int_option(mosq, MOSQ_OPT_SEND_MAXIMUM, 65535);

    for (int i = 1; i <= NUM_MSG; i++)
    {
        /* ------------------- DELAY CALC -------------------*/
        //sRet.wssl_msg = "1657888424062511|MY_MESSAGE|10000"; /* ---- USING ONLY MQTT ---*/
        if (i==1)
             time_first = rget_timeStamp();
        else if (i==(NUM_MSG)){
            time_last = rget_timeStamp();
        }
        /* ------------------- DELAY CALC -------------------*/

        // Remove comment of ONE of the three options to publish a valid message, generate errors, or generate delays, respectively:
        publish_messages(sRet, mosq);
        //generate_errorMessages(sRet, mosq, i);
        //generate_delayError(sRet, mosq, i);

        size_send = sRet.table->size_array;
        //cout << "\nThe array of struct in Sender has %d connections" << size_send << endl;
        
        // Print Sender table with all existing connections 
        cout << "  timeStamp(us)  |   MESSAGE   | Seq. Number" << endl;
        for(int i=0; i<size_send; i++){
            cout << sRet.table[i].timeStamp << " |  ";
            cout << sRet.table[i].data << "  |   ";
            cout << sRet.table[i].seq_number << endl << endl;
        }
        usleep(3000); //Define send frequency 
        mosquitto_loop(mosq,-1,1);
    }
    /* ------------------- DELAY CALC -------------------*/
    send_time = time_last - time_first;
    cout << "Send time for " << NUM_MSG << " message(s): " << send_time << " ms" << endl;
    /* ------------------- DELAY CALC -------------------*/
    
    mosquitto_disconnect(mosq);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
    return 0;
}

/* ----------------------- Function responsible for publishing messages with erros for testing purpose ----------------------- */
void generate_errorMessages(struct wssl_send_return sRet, struct mosquitto *mosq, int i)
{
        const void *msg_mqtt;

        if(i == 2){
            cout << "\n------------------------------------ MSG ----------------------------------------" << endl << endl;
            sRet = init_wssl_send("Sending a wrong signature", "PK01", receiverID, sRet);
            sRet.wssl_msg.erase(8, 3); //Sabotage message byte 
            msg_mqtt = sRet.wssl_msg.c_str();  
            mosquitto_publish(mosq, NULL, "test/wssl", sRet.wssl_msg.length(), msg_mqtt, 0, false);
        }else if (i == 4){
            cout << "\n------------------------------------ MSG ----------------------------------------" << endl << endl;
            sRet = init_wssl_send("Sending a not existent Sender ID", "PK02", receiverID, sRet);
            msg_mqtt = sRet.wssl_msg.c_str();        
            mosquitto_publish(mosq, NULL, "test/wssl", sRet.wssl_msg.length(), msg_mqtt, 0, false);
        }else if (i == 6){
            usleep(11000);
            sRet = init_wssl_send("MESSAGE OK", "PK01", receiverID, sRet);
            msg_mqtt = sRet.wssl_msg.c_str();        
            mosquitto_publish(mosq, NULL, "test/wssl", sRet.wssl_msg.length(), msg_mqtt, 0, false);
        }else{
            sRet = init_wssl_send("MESSAGE OK", "PK01", receiverID, sRet);
            msg_mqtt = sRet.wssl_msg.c_str();        
            mosquitto_publish(mosq, NULL, "test/wssl", sRet.wssl_msg.length(), msg_mqtt, 0, false);
        }

}
/* ----------------------- Function responsible for publishing messages with delays (testing purpose only) ----------------------- */
void generate_delayError(struct wssl_send_return sRet, struct mosquitto *mosq, int i)
{
        const void *msg_mqtt;

        if(i % 11 == 0){
            usleep(11000);
            //cout << "\n------------------------------------ MSG ----------------------------------------" << endl << endl;
            sRet = init_wssl_send("Generating a delayed message", "PK01", receiverID, sRet);
            msg_mqtt = sRet.wssl_msg.c_str();  
            mosquitto_publish(mosq, NULL, "test/wssl", sRet.wssl_msg.length(), msg_mqtt, 0, false);
        }else{
            sRet = init_wssl_send("MESSAGE OK", "PK01", receiverID, sRet);
            msg_mqtt = sRet.wssl_msg.c_str();        
            mosquitto_publish(mosq, NULL, "test/wssl", sRet.wssl_msg.length(), msg_mqtt, 0, false);
        }
}

/* ---------------- Function responsible for calculating the time used to calculate delay (testing purpose only) ---------------- */
long int rget_timeStamp()
{
    long int timeStamp = static_cast<long int>
        (chrono::duration_cast<chrono::milliseconds>(chrono::high_resolution_clock::now().time_since_epoch()).count());
 
    return timeStamp;
}
