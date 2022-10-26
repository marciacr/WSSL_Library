/* ------------------------------------------------ LIBRARY INCLUDES ----------------------------------------------- */
#include <iostream>
#include <chrono>             // Chrono library is used to deal with date and time.
#include <iomanip>            // put_time()
#include <string>             // string from C
#include "lib_wssl.h"         // WSSL Library  
#include "CryptoIdentity.h"   // VORTEX Library for digital signatures
#include <fstream>

/* ------------------------------------------  DEFINES & GLOBAL VARIABLES ------------------------------------------ */

#define EMPTY_TABLE 0
#define OK 1
#define REPLACE_MSG 2
#define NEW_MSG 3
#define delaySndMAX 10000
#define delayRcvMAX 20000
#define WriteFile 0
#define LogError 0

enum status {sts_OK, sts_DUP, sts_wrongSEQ, sts_lostMSG, sts_delaySnd, sts_delayRcv};
// Declare namespace standard library (std)
using namespace std;      

// The number of connections inside the table is zero and the table status is OK
int rnum_connect = 0;
int rtable_status = OK; 
ofstream myFile;
ofstream logError;

/* ----- Function that calculates the current time (timeStamp) in microseconds and store in a long int variable ----- */
long int rget_timeStamp()
{
    long int timeStamp = static_cast<long int>
        (chrono::duration_cast<chrono::microseconds>(chrono::high_resolution_clock::now().time_since_epoch()).count());
    return timeStamp;
}

/* ---------- Security Entity responsible for verify signature and return the message with safety entities ---------- */
struct wssl_rcv_return entity_security_rcv(string wssl_msg, string id_sender, struct wssl_rcv_return rRet)
{
    //cout << "\n<<<<<<<<<< RECEIVER SIDE >>>>>>>>>" << endl << endl;
    int signSize = CryptoIdentity::SIGN_SIZE;
    int strSize = wssl_msg.length() - signSize;
    int fullSize = wssl_msg.length();
    
    // cout << "\nstrSigned: "<< wssl_msg <<  endl;
    // cout << "strSize: " << strSize << endl;
    // cout << "fullsize: " << fullSize << endl;
    
    CryptoIdentity* idLoaded = CryptoIdentity::load("rcvFile");    
    rRet.plain_text = idLoaded->verifySignature(wssl_msg, idLoaded->getKnownKey(id_sender));     
    return rRet;
}

/* ----------- Safety Entity responsible for separating the Time Stamp and Sequence ID from the message ----------- */
struct wssl_rcv_return entity_safety_rcv(string decript_msg, string id_sender, long int rcv_TimeStamp, struct wssl_rcv_return rRet)
{
    //cout << "\n<<<<<<<<<<<< SAFETY >>>>>>>>>>>>>" << endl;
    int i = 0;
    /* Gets the position from the separators '|' inside the string */
    int pos = decript_msg.find('|');             // Stores the '|' position separating the TimeStamp from the rest
    string temp1 = decript_msg.substr(pos+1);    // Temp string stores the string starting on position till the end
    int pos2 = temp1.find("|");                  // Stores the '|' position separating Plain text from sequence number

    /* Spliting the received string to get the time stamp, encrypted message and sequence ID */
    long int msgTimeStamp = stol(decript_msg.substr(0,pos));
    string msg = temp1.substr(0, pos2);
    int seq_number = stol(temp1.substr(pos2+1));

    // cout << "msg: " << msg << endl;
    // cout << "arriving time stamp: " << msgTimeStamp << endl;
    // cout << "seq number: " << seq_number << endl;

    /*  Check if the table is not empty and if status is OK */
    if((rnum_connect != EMPTY_TABLE) && (rtable_status == OK)){
        if(WriteFile)
            myFile.open("delayReceiver.csv", ios::out | ios::app);
        if(LogError)
            logError.open("logErrors.csv", ios::out | ios::app);
            
        /*  Go through the existing connections looking for the sender  */
        for(i=0; i<rnum_connect; i++){   

            /*  IF the destination in current array position (i) is not the same of id_dest, 
                THEN bypass the conditions and goes for the next array position (i+1) */
            if(rRet.table[i].sender != id_sender){
                // cout << "\nDestinatary " << rRet.table[i].sender <<  " is different from " << 
                //     id_sender << ", going for the next position of the array... "<< endl;
                // cout << "-->" <<endl;
            }

            /*  IF it finds the destination inside the array, 
                THEN replace the data and timeStamp and increment sequence number by 1  */
            if(rRet.table[i].sender == id_sender){
                //cout << "\nConexion found, replacing the data inside the position "<< i 
                    //<< " with new packet info... " <<endl;

                /* --------------- Check conditions for the sequence number integrity --------------- */
                if ((seq_number-rRet.table[i].seq_number) == OK ){        //IF it is sequential, status: 0 -> The message is OK 
                    cout << "The sequence ID is OK (flag = 0), continue..." << endl;
                    rRet.table[i].status = sts_OK;
                     if(logError)
                         logError  << "Message " << seq_number << ", " << "Status: " << rRet.table[i].status << ", " << endl; 

                }else if((seq_number-rRet.table[i].seq_number) == 0){    //IF it is zero, status: 1 -> The message was duplicated
                    cout << "\n!!! The message is a duplication, setting status flag for duplication (flag = 1) !!!! " << endl;
                    rRet.table[i].status = sts_DUP;
                    if(logError)
                         logError  << "Message " << seq_number << ", " << "Status: " << rRet.table[i].status << ", " << endl; 
                
                }else if((seq_number-rRet.table[i].seq_number) < 0){  //IF NOT 1 or 0, status: 2 -> The message is out-of-order
                    cout << " \n!!! There is a message out of sequence, setting status flag for wrong sequence number (flag = 2) !!!" << endl;
                    rRet.table[i].status = sts_wrongSEQ;
                    if(LogError)
                        logError  << "Message " << seq_number << ", " << "Status: " << rRet.table[i].status << ", " << endl;  
                }else {  //IF NOT 1 or 0, status: 3 -> The message has a wrong sequence ID (messages may have been lost)
                    cout << " \n!!! Lost messages, setting status flag for wrong sequence number (flag = 3) !!!" << endl;
                    rRet.table[i].status = sts_lostMSG;
                    if(LogError)
                        logError  << "Message " << seq_number << ", " << "Status: " << rRet.table[i].status << ", " << endl;  
                }

                // Replace table position information with the same sender
                if(rRet.table[i].status != sts_wrongSEQ && rRet.table[i].status != sts_DUP){

                    /* Calculate the receive delay by subtracting the time the message arrived by the time the message was sent  */
                    rRet.table[i].delay_rcv = rcv_TimeStamp - msgTimeStamp; 
                    /*  Calculating delay between arriving of the two messages  */
                    rRet.table[i].delay_send = msgTimeStamp - rRet.table[i].timeStamp;

                    // cout << "My rcv_TimeStamp: " << rcv_TimeStamp << endl;
                    // cout << "My msgTimeStamp: " << msgTimeStamp << endl;
                    rRet.table[i].data = msg;
                    rRet.table[i].seq_number = seq_number;
                    rRet.table[i].timeStamp = msgTimeStamp; 

                    /* --------------- Check conditions for delay send and delay receive --------------- */
                    if (rRet.table[i].delay_send > delaySndMAX){ 
                        //IF delay send is bigger than the MAX defined, status: 4 -> There is an unacceptable delay between the messages
                        //cout << "\n!!! There is a big delay between the messages, setting status flag for delay between arriving messages (flag = 4) !!!" << endl
                        if(LogError)
                            logError  << "Message " << rRet.table[i].seq_number << ", " << "Status: " << sts_delaySnd << ", " << endl; 

                    }

                    if (rRet.table[i].delay_rcv > delayRcvMAX){ 
                        //IF delay receive is bigger than the MAX defined, status: 5 -> 
                        // -> There is an unacceptable delay between the timeStamp inside the message and the real received time
                        //cout << "\n!!! The message's send time is too different from the message's received time, please check the connection (flag = 5) !!!" << endl;
                        if(LogError)
                            logError  << "Message " << rRet.table[i].seq_number << ", " << "Status: " << sts_delayRcv << ", " << endl;  

                    }
                }
   
                //Send data to csv file
                if(WriteFile)
                    myFile  << "Delay_" << rRet.table[i].seq_number << ", " << rRet.table[i].delay_send << ", " << endl;
                    //myFile  << "Delay_" << rRet.table[i].seq_number << ", " << rRet.table[i].delay_send << ", " << rRet.table[i].delay_rcv << endl; 

                //Update the message with the receiver information: TimeStamp | Message Data | Sequence Number | Status | Delay_send | Delay_rcv
                rRet.plain_text = to_string(rRet.table[i].timeStamp) + "|" + rRet.table[i].data + "|" 
                    + to_string(rRet.table[i].seq_number) + "|" + to_string(rRet.table[i].status) + "|" 
                        + to_string(rRet.table[i].delay_send) + "|" + to_string(rRet.table[i].delay_rcv);
                
                // Message was replaced, so the number of connections inside the table is still the same
                rtable_status = REPLACE_MSG; 
            }  
        }
        
        /*  IF table status is OK it means the sender doesn't exists inside the table yet, 
            THEN create a new connection */
        if(rtable_status == OK){
            cout << "\n<< Adding a new packet inside the table in position [" << rnum_connect << "] >>" << endl;

            /* --------------- Check conditions for the sequence number integrity --------------- */
            rRet.table[rnum_connect].seq_number = 0;
            if ((seq_number-rRet.table[rnum_connect].seq_number) == OK )
            {   //IF it is sequential, status: 0 -> The message is OK 
                cout << "The sequence ID is OK (flag = 0), continue..." << endl;
                rRet.table[rnum_connect].status = sts_OK;
                if(LogError)
                    logError  << "Message " << seq_number << ", " << "Status: " << rRet.table[rnum_connect].status << ", " << endl; 

            }else if((seq_number-rRet.table[rnum_connect].seq_number) != OK)
            {   //IF NOT 1, status: 3 -> The message has a wrong sequence ID (messages may have been lost)
                cout << " \n!!! Lost messages, setting status flag for wrong sequence number (flag = 3) !!!" << endl;
                rRet.table[rnum_connect].status = sts_lostMSG;
                if(LogError)
                    logError  << "Message " << seq_number << ", " << "Status: " << rRet.table[rnum_connect].status << ", " << endl;  
            }         

            rRet.table[rnum_connect].delay_rcv = rcv_TimeStamp - msgTimeStamp; 
            rRet.table[rnum_connect].delay_send = 0;

            // Replace table position information with the same sender
            rRet.table[rnum_connect].data = msg;
            rRet.table[rnum_connect].sender = id_sender;          //New sender
            rRet.table[rnum_connect].seq_number = seq_number;     //Sequence number is received from message
            rRet.table[rnum_connect].timeStamp = msgTimeStamp;  

            /* --------------- Check conditions for delay receive --------------- */
            if (rRet.table[rnum_connect].delay_rcv > delayRcvMAX){ 
                //IF delay receive is bigger than the MAX defined, status: 5 -> 
                // -> There is an unacceptable delay between the timeStamp inside the message and the real received time
                cout << "\n!!! The message's send time is too different from the message's received time, please check the connection (flag = 5) !!!" << endl;
                if(LogError)
                    logError  << "Message " << rRet.table[rnum_connect].seq_number << ", " << "Status: " << sts_delayRcv << ", " << endl;  

            }

            if(WriteFile)
                myFile  << "Delay_" << rRet.table[i].seq_number << ", " << rRet.table[i].delay_send << ", " << endl;
                //myFile  << "Delay_" << rRet.table[rnum_connect].seq_number << ", " << rRet.table[rnum_connect].delay_send << ", " << rRet.table[rnum_connect].delay_rcv << endl; 

            //Update the message with the receiver information: TimeStamp | Message Data | Sequence Number | Status | Delay_send | Delay_rcv
            rRet.plain_text = to_string(rRet.table[rnum_connect].timeStamp) + "|" + rRet.table[rnum_connect].data + "|" 
                + to_string(rRet.table[rnum_connect].seq_number) + "|" + to_string(rRet.table[rnum_connect].status) + "|" 
                    + to_string(rRet.table[rnum_connect].delay_send) + "|" + to_string(rRet.table[rnum_connect].delay_rcv);

            //New message/connection was created and number of connections increase by 1
            rtable_status = NEW_MSG;
            rnum_connect++;    
            rRet.table->size_array = rnum_connect;            
        }
    }

    //IF table is empty, THEN create first connection with sequence number 1
    if(rnum_connect == EMPTY_TABLE){
        
        if(WriteFile)
            myFile.open("delayReceiver.csv", ios::out | ios::trunc);
        if(logError)
            logError.open("logErrors.csv", ios::out | ios::trunc);

        /* --------------- Check conditions for the sequence number integrity --------------- */
        if ((seq_number - EMPTY_TABLE) == OK )
        {   //IF it is sequential, status: 0 -> The message is OK 
            cout << "The sequence ID is OK (flag = 0), continue..." << endl;
            rRet.table[0].status = sts_OK;
            if(LogError)
                logError  << "Message " << seq_number << ", " << "Status: " << rRet.table[0].status << ", " << endl; 

        }else if((seq_number - EMPTY_TABLE) != OK)
        {   //IF NOT 1, status: 3 -> The message has a wrong sequence ID (messages may have been lost)
            cout << " \n!!! Lost messages, setting status flag for wrong sequence number (flag = 3) !!!" << endl;
            rRet.table[0].status = sts_lostMSG;
            if(LogError)
                logError  << "Message " << seq_number << ", " << "Status: " << rRet.table[0].status << ", " << endl;  
        }

        rRet.table[0].delay_rcv = rcv_TimeStamp - msgTimeStamp; 
        rRet.table[0].delay_send = 0;

        //cout << "\nMy Receiver table is empty, creating new packet... " << endl;
        rRet.table[0].data = msg;
        rRet.table[0].sender = id_sender;
        rRet.table[0].seq_number = seq_number;
        rRet.table[0].timeStamp = msgTimeStamp;
        
        /* --------------- Check conditions for delay receive --------------- */
        if (rRet.table[0].delay_rcv > delayRcvMAX){ 
            //IF delay receive is bigger than the MAX defined, status: 5 -> 
            // -> There is an unacceptable delay between the timeStamp inside the message and the real received time
            cout << "\n!!! The message's send time is too different from the message's received time, please check the connection (flag = 5) !!!" << endl;
            if(LogError)
                logError  << "Message " << rRet.table[0].seq_number << ", " << "Status: " << sts_delayRcv << ", " << endl;  

        }

        //Number of connections now is 1
        rnum_connect = 1;
        rRet.table->size_array = rnum_connect;
        
        //Send data to csv file
        if(WriteFile)
            myFile  << "Delay_" << rRet.table[i].seq_number << ", " << rRet.table[i].delay_send << ", " << endl;
            //myFile  << "Delay_" << rRet.table[0].seq_number << ", " << rRet.table[0].delay_send << ", " << rRet.table[0].delay_rcv << endl; 
        // if(logError)
        //     logError  << "Message " << rRet.table[0].seq_number << ", " << "Status: " << rRet.table[0].status << ", " << endl; 
            
        //Update the message with the receiver information: TimeStamp | Message Data | Sequence Number | Status | Delay_send | Delay_rcv
        rRet.plain_text = to_string(rRet.table[0].timeStamp) + "|" + rRet.table[0].data + "|" 
            + to_string(rRet.table[0].seq_number) + "|" + to_string(rRet.table[0].status) + "|" 
                + to_string(rRet.table[0].delay_send) + "|" + to_string(rRet.table[0].delay_rcv);

        if(WriteFile)
            myFile.close();
        if(LogError)
            logError.close();            
    }

    //Finished function, so the table status is OK again
    rtable_status = OK; 
    if(WriteFile)
        myFile.close();
    if(LogError)
        logError.close();   
    return rRet;
}

/*  WSSL Function, responsible for calling the safety and security layer  */
struct wssl_rcv_return wssl_rcv_msg(string wssl_msg, string id_sender, struct wssl_rcv_return rRet){
    
    //Stores the time that the message was received to calculate delay between sender and receiver 
    long int rcv_TimeStamp = rget_timeStamp(); 
    //Calls Security entity passing the signed message, the destination ID and the struct in the parameters, the return updates the struct itself
    rRet = entity_security_rcv(wssl_msg, id_sender, rRet);
    if(rRet.plain_text == "error"){
        if(LogError){
            logError.open("logErrors.csv", ios::out | ios::app);
            //cout << "Warning, something is wrong when verifying the signature!" << endl;
            logError  << "Security error!" << endl; 
            logError.close();
        }
        return rRet;
    }else{
        //Calls Safety entity passing the same parameters, but now with the message received from security
        rRet = entity_safety_rcv(rRet.plain_text, id_sender, rcv_TimeStamp, rRet);
        //Return the original message for the application
        return rRet;
    }
    
    /*------------------------ ONLY SAFETY TEST ------------------------*/
    // rRet = entity_safety_rcv(rRet.plain_text, id_sender, rcv_TimeStamp, rRet);
    // return rRet;
}

/*  The library starts here  */
struct wssl_rcv_return init_wssl_rcv(string wssl_msg, string id_sender, struct wssl_rcv_return rRet){

    //Starts library by calling the wssl_send_msg and updates the struct
    rRet = wssl_rcv_msg(wssl_msg, id_sender, rRet);

    //The library return is the struct itself
    return rRet;
}

