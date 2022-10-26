/* ------------------------------------------------ LIBRARY INCLUDES ----------------------------------------------- */
#include <iostream>
#include <chrono>             // Chrono library is used to deal with date and time.
#include <iomanip>            // put_time()
#include <string>             // string from C
#include <unistd.h>           // sleep()
#include "lib_wssl.h"         // WSSL Library  
#include "CryptoIdentity.h"   // VORTEX Library for digital signatures
#include <string.h>

/* ------------------------------------------  DEFINES & GLOBAL VARIABLES ------------------------------------------ */
#define EMPTY_TABLE 0
#define OK 1
#define REPLACE_MSG 2
#define NEW_MSG 3

using namespace std;    

int num_connect = EMPTY_TABLE;
int table_status = OK;  

/*------------------ Generating sequence number errors ------------------*/
int flag = 0;
int test_seq_number(int seq_number){
    if(seq_number == 13){
        seq_number +=2;
    }else if (seq_number == 8 && flag == 0){
        seq_number = 8;
        flag = 1;
    }else if(seq_number == 11 && flag == 1){
        seq_number = 9;
        flag = 2;
    }else {
        seq_number ++;
    }
    return seq_number;
}


/* ----- Function that calculates the current time (timeStamp) in microseconds and store in a long int variable ----- */
long int get_timeStamp(){
    long int timeStamp = static_cast<long int>
        (chrono::duration_cast<chrono::microseconds>(chrono::high_resolution_clock::now().time_since_epoch()).count());

    return timeStamp;
}

/* ----------- Safety Entity responsible for adding Time Stamp and Sequence ID into the message structure ----------- */
struct wssl_send_return entity_safety_send(string msg, string id_dest, struct wssl_send_return sRet){

    string wssl_msg;
    long int timeStamp = get_timeStamp();
    
    // Check IF the table is not empty and IF status is OK
    if((num_connect != EMPTY_TABLE) && (table_status == OK)){
        
        // IF the condition is met, it goes through each element of the table looking for the destination ID 
        for(int i=0; i<num_connect; i++){
            
            // IF the destination in current array position (i) is not the same of id_dest, THEN bypass the conditions and goes for the next array position (i+1)
            if(sRet.table[i].dest != id_dest){
                // cout << "\nRecipient " << sRet.table[i].dest <<  " is different from " << 
                //     id_dest << ", going for the next position of the array... "<< endl;
            
            // IF it finds the destination ID inside the array, THEN replace the data and timeStamp and increment sequence number by 1
            }else if(sRet.table[i].dest == id_dest){
                // cout << "\nConexion found, replacing the data inside the position "<< i 
                //     << " with new packet info..." <<endl;

                // Here message is replaced, thus the number of connections will not change
                sRet.table[i].data = msg;
                //sRet.table[i].timeStamp = timeStamp;
                //Comment here if using the line to generate erros
                sRet.table[i].seq_number ++; 
                //Remove commentary to generate errors in the seq. number
                sRet.table[i].seq_number = test_seq_number(sRet.table[i].seq_number); 
                
                wssl_msg = to_string(sRet.table[i].timeStamp) + "|" + sRet.table[i].data + "|" + to_string(sRet.table[i].seq_number);         
                table_status = REPLACE_MSG;
             }
        }
        
        // IF table status is OK it means the destination doesn't exists inside the table yet, THEN create new connection
        if(table_status == OK){
            cout << "\n<< Adding a new connection inside the Sender table in position [" << num_connect << "] >>" << endl;

            // New message/connection is created and the number of connections increases by 1
            sRet.table[num_connect].data = msg;
            sRet.table[num_connect].dest = id_dest;  
            sRet.table[num_connect].seq_number = 1; 
            sRet.table[num_connect].timeStamp = timeStamp;  
            
            wssl_msg = to_string(sRet.table[num_connect].timeStamp) + "|" + sRet.table[num_connect].data + "|" + to_string(sRet.table[num_connect].seq_number);
            table_status = NEW_MSG;

            // Increase the number of connections by 1 and store the table size
            num_connect ++;    
            sRet.table->size_array = num_connect;
        }

    // IF table is empty, THEN create first connection of the table
    } else if(num_connect == EMPTY_TABLE){
        //cout << "\nSender table is empty, creating new packet...." << endl;

        sRet.table[0].data = msg;
        sRet.table[0].dest = id_dest;
        sRet.table[0].seq_number = 1;
        sRet.table[0].timeStamp = timeStamp;

        wssl_msg = to_string(sRet.table[0].timeStamp) + "|" + sRet.table[0].data + "|" + to_string(sRet.table[0].seq_number);

        //Set number of connections to 1 and store the table size
        num_connect = 1;
        sRet.table->size_array = num_connect;
    }

    //Update the message inside the table with the updated safety entities: TimeStamp | Message Data | Sequence Number
    sRet.wssl_msg = wssl_msg;

    //Table status is set to OK again and the function returns the updated struct
    table_status = OK;
    return sRet;
}

/* --- Receives the message with safety entities, sign and returns the struct sRet updated with the signed message --- */
struct wssl_send_return entity_security_send(string safe_msg, string id_sender, struct wssl_send_return sRet){

    /* --------------------------------- IDs CREATION --------------------------------------
        - Creating the Sender and Receiver identities inside the files to exchange keys.
        - It is necessary to create and save only once, than it can be commented inside the code.
       -----------------------------------------------------------------------------------  */
    // string path = "senderFile";
	// string label = "senderLabel";
    // string path2 = "rcvFile";
	// string label2 = "rcvLabel";
    // string path3 = "sender2File";
	// string label3 = "sender2Label";

	// auto* id1 = new CryptoIdentity(path, label);
    // auto* id2 = new CryptoIdentity(path2, label2);
    // auto* id3 = new CryptoIdentity(path3, label3);

    // id1->addKnownIdentity("PK02", id2->pk);
    // std::cout << id1->save() << std::endl;
    // id2->addKnownIdentity("PK01", id1->pk);
    // id2->addKnownIdentity("PK03", id3->pk);
    // std::cout << id2->save() << std::endl;
    // id3->addKnownIdentity("PK01", id2->pk);
    // std::cout << id3->save() << std::endl;
    /* ---------------------------------- END IDs CREATION ---------------------------------- */

    // Load identities inside the Sender file
    CryptoIdentity* idLoaded1 = CryptoIdentity::load("senderFile");
    //CryptoIdentity* idLoaded2 = CryptoIdentity::load("sender2File");
    //cout << "safe_msg: " << safe_msg << endl;
    
    int strSize = safe_msg.length();
	int signSize = CryptoIdentity::SIGN_SIZE;
	int fullSize = strSize + signSize;
    //int fullSize = strSize;/* ---------- TEST SAFETY ONLY ---------*/
    
    // Sign the message by calling sign() method
    string strSigned = idLoaded1->sign(safe_msg, strSize);
    //string strSigned = idLoaded2->sign(safe_msg, strSize);

    //cout << "strSigned: " << strSigned<< endl;
    // cout << "strSize: " << strSize << endl;
    // cout << "fullsize: " << fullSize << endl;

    //Verifies if the signature process succeeded
    if(strSigned == "error"){
        cout << "\n ------> Failed to sign, Security Error! <------" << endl;

    }else{
        if(fullSize < 100){
            string s = "0" + to_string(fullSize);
            sRet.wssl_msg = s + id_sender + strSigned;
        }else{
            string s = to_string(fullSize);
            sRet.wssl_msg = s + id_sender + strSigned;
        }
    }
    
    //Returns the updated struct with WSSL message
    return sRet;

}

/* ------------------------ WSSL function responsible for calling the safety and security layer ----------------------- */
struct wssl_send_return wssl_send_msg(string msg, string id_sender, string id_dest, struct wssl_send_return sRet)
{
    //sRet.wssl_msg = "1657888424062511|MY_MESSAGE|10000";/* ------ TEST SECURITY ONLY ---------*/

    // Calls Safety entity passing the message, the destination ID and the struct in the parameters, the return updates the struct itself
    sRet = entity_safety_send(msg, id_dest, sRet);
    //cout << "\nSafety message: " << sRet.wssl_msg << endl;

    // Calls Security entity passing the same parameters, but now with the message received from safety
    sRet = entity_security_send(sRet.wssl_msg, id_sender, sRet);
    //cout << "Security message: " << sRet.wssl_msg << endl;

    // Return the struct updated with the signed WSSL message  
    return sRet;
}

/* ------------------------------------------ The WSSL library starts here ------------------------------------------- */
struct wssl_send_return init_wssl_send(string msg, string id_sender, string id_dest, struct wssl_send_return sRet)
{
    sRet = wssl_send_msg(msg, id_sender, id_dest, sRet);   
    return sRet;
}

