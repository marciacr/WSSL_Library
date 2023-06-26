
#include "libwssl_class.h"

int numConnect = EMPTY_TABLE;
int tableStatus = OK;  

LibWssl Sender;

/* ------------------ Evaluation Purporse Only ------------------ */
/**
 * SEQUENCE NUMBER EVALUATION: Generate different sequence numbers to test the detection of different failures
 * - DUPLICATED message
 * - OUT-OF-ORDER message
 * - LOST message
*/
int flag = 0;
int test_seqNumber(int seqNumber){
    if(seqNumber == 13){
        seqNumber +=2;
    }else if (seqNumber == 8 && flag == 0){
        seqNumber = 8;
        flag = 1;
    }else if(seqNumber == 11 && flag == 1){
        seqNumber = 9;
        flag = 2;
    }else {
        seqNumber ++;
    }
    return seqNumber;
}
/* ----------------------- Evaluation End ----------------------- */


/**
 * Safety Entity inside the Sender, responsible for appending Time Stamp and Sequence Number into the message
 * @param msg Message received from application
 * @param destID Destination identificator, also called label
 * @param timeStamp Time the message was sent in microseconds 
 * @param sRet SenderReturn object
 * @return sRet Updated SenderReturn object
 * */
SenderReturn entity_safety_send(std::string msg, std::string destID, long int timeStamp, SenderReturn sRet){

    std::string safeMsg;
    
    // Check IF the table is not empty and IF status is OK
    if((numConnect != EMPTY_TABLE) && (tableStatus == OK)){
        
        /**
         * Goes through each element of the table looking for the destination ID: 
         * IF it finds the destination ID inside the array, THEN replace the data and timeStamp and increment sequence number by 1
         * Here message is replaced, thus the number of connections will not change
         * */
        for(int i=0; i<numConnect; i++){
            if(sRet.table[i].destID == destID){
                // std::cout << "\nConexion found, replacing the data inside the position "<< i << " with new packet info..." <<std::endl;

                sRet.table[i].data = msg;
                sRet.table[i].timeStamp = timeStamp;
                sRet.table[i].seqNumber ++; 
                // Comment line above and remove comment below to generate errors in the seq. number
                // sRet.table[i].seqNumber = test_seqNumber(sRet.table[i].seqNumber); 
                
                safeMsg = std::to_string(sRet.table[i].timeStamp) + Sender.delimiter + sRet.table[i].data + Sender.delimiter + std::to_string(sRet.table[i].seqNumber);         
                tableStatus = REPLACE_MSG;
             }
        }
        
        /**
         * IF table status did not change (status == OK):
         * The destination doesn't exists inside the table yet, THEN create new connection
         * New message/connection is created and the number of connections increases by 1
         * */
        if(tableStatus == OK){
            // std::cout << "\n<< Adding a new connection inside the Sender table in position [" << numConnect << "] >>" << std::endl;

            sRet.table[numConnect].data = msg;
            sRet.table[numConnect].destID = destID;  
            sRet.table[numConnect].seqNumber = 1; 
            sRet.table[numConnect].timeStamp = timeStamp;  
            
            safeMsg = std::to_string(sRet.table[numConnect].timeStamp) + Sender.delimiter + sRet.table[numConnect].data + Sender.delimiter + std::to_string(sRet.table[numConnect].seqNumber);
            tableStatus = NEW_MSG;

            numConnect ++;    
            sRet.table->size = numConnect;
        }

    /**
     * IF table is empty, THEN create first connection of the table
     * Set number of connections and the sequence number to 1 
     * */
    } else if(numConnect == EMPTY_TABLE){
        // std::cout << "\nSender table is empty, creating new packet...." << std::endl;

        sRet.table[0].data = msg;
        sRet.table[0].destID = destID;
        sRet.table[0].seqNumber = 1;
        sRet.table[0].timeStamp = timeStamp;

        numConnect = 1;
        sRet.table->size = 1;

        safeMsg = std::to_string(sRet.table[0].timeStamp) + Sender.delimiter + sRet.table[0].data + Sender.delimiter + std::to_string(sRet.table[0].seqNumber);
    }

    //Update the message inside the table with the updated safety entities: TimeStamp | Message Data | Sequence Number
    sRet.wsslMsg = safeMsg;

    tableStatus = OK;
    return sRet;
}

/**
 * Receives the message with safety entities (safeMsg), Sign the message with Sender private key (sk), and returns the SenderReturn object (sRet) updated with the signed message (wsslMsg)
 * @param safeMsg Message from safety entity that contains the sequence number and time stamp
 * @param senderID Sender identificator, also called label
 * @param path Path name of the Sender identity
 * @param sRet SenderReturn object
 * @return sRet Updated SenderReturn object
 * */
SenderReturn entity_security_send(std::string safeMsg, std::string senderID, std::string path, SenderReturn sRet){

    CryptoIdentity* idLoaded = CryptoIdentity::load(path);
    std::string aux;
    std::string strSigned;
    //std::cout << "safe_msg: " << safe_msg << std::endl;

    int strSize = safeMsg.length();
	int signSize = CryptoIdentity::SIGN_SIZE;
	int fullSize = strSize + signSize;
    
    strSigned = idLoaded->sign(safeMsg, strSize);
    //std::cout << "strSigned: " << strSigned<< std::endl;
    // std::cout << "strSize: " << strSize << std::endl;
    // std::cout << "fullsize: " << fullSize << std::endl;

    // Verifies if the signature was successful, if yes append senderID and signed message size to the wsslMsg
    if(strSigned == "error"){
        throw std::runtime_error("Sender failed to sign message!");

    }else{
        if(fullSize < 100){
            aux = "0" + std::to_string(fullSize);
            sRet.wsslMsg = aux + senderID + strSigned;
        }else{
            aux = std::to_string(fullSize);
            sRet.wsslMsg = aux + senderID + strSigned;
        }
    }
    return sRet;

}

/**
 * WSSL send function is responsible for calling the safety and security entities
 * @param msg Message received from application
 * @param senderID Sender identificator, also called label
 * @param destID Destination identificator, also called label
 * @param path Path name of the Sender identity
 * @param timeStamp Time the message was sent in microseconds 
 * @param sRet SenderReturn object
 * @return sRet Updated SenderReturn object
 * */
SenderReturn wssl_send_msg(std::string msg, std::string senderID, std::string destID, std::string path, long int timeStamp, SenderReturn sRet)
{
    // sRet.wsslMsg = "1657888424062511|MY_MESSAGE|10000";/* ------ EVALUATION SECURITY ONLY ---------*/

    sRet = entity_safety_send(msg, destID, timeStamp, sRet);
    // std::cout << "\nSafety message: " << sRet.wsslMsg << std::endl;
    sRet = entity_security_send(sRet.wsslMsg, senderID, path, sRet);
    // std::cout << "Security message: " << sRet.wsslMsg << std::endl;

    return sRet;
}

SenderReturn LibWssl::init_wssl_snd(std::string msg, std::string senderID, std::string destID, std::string path, SenderReturn sRet)
{
    long int timeStamp = Sender.get_time_stamp_micro();

    delete_old_connexions_snd(sRet);

    sRet = wssl_send_msg(msg, senderID, destID, path, timeStamp, sRet);   
    return sRet;
}

void LibWssl::delete_old_connexions_snd(SenderReturn sRet)
{
    float sec = 1000000;
    long int time_now = Sender.get_time_stamp_micro();
    
    for (int i = 0; i < numConnect; i++)
    {
        if( (time_now - sRet.table[i].timeStamp) / sec >= LIM_TIME_SEC)
        {
            for (int j = i; j< numConnect-1; j++)
                sRet.table[j] = sRet.table[j+1];
            
            std::cout << "Deleted position [" << i << "]" << std::endl;
            numConnect --;
            sRet.table->size = numConnect;
            i--;
        }
    }
}


