
#include "libwssl_class.h"

#define writeDelay 0
#define writeError 0

enum status {sts_OK, sts_DUP, sts_wrongSEQ, sts_lostMSG, sts_delaySnd, sts_delayRcv};
   
LibWssl Rcv;

// The number of connections inside the table is zero and the table status is OK
int numConnect = 0;
int tableStatus = OK; 

// Log files for evaluation purpose only
std::ofstream logDelay;
std::ofstream logError;

/**
 * Receives the message from sender (wsslMsg), try to remove the signature using Sender public key (pk), 
 * and returns the ReceiverReturn object (rRet) updated with the plain message (msg)
 * @param wsslMsg Signed message received from Sender
 * @param senderID Sender identificator, also called label
 * @param path Path name of the Sender identity
 * @param rRet ReceiverReturn object
 * @return Updated ReceiverReturn object (rRet), if success. Returns "error" if something goes wrong
 * */
ReceiverReturn entity_security_rcv(std::string wsslMsg, std::string senderID, std::string path, ReceiverReturn rRet)
{
    int signSize = CryptoIdentity::SIGN_SIZE;
    int strSize = wsslMsg.length() - signSize;
    int fullSize = wsslMsg.length();
    
    // std::cout << "\nstrSigned: "<< wsslMsg <<  std::endl;
    // std::cout << "strSize: " << strSize << std::endl;
    // std::cout << "fullsize: " << fullSize << std::endl;
    
    CryptoIdentity* idLoaded = CryptoIdentity::load(path);    
    rRet.plainText = idLoaded->verifySignature(wsslMsg, idLoaded->getKnownKey(senderID));     
    //std::cout << rRet.plainText << std::endl;
    return rRet;
}

/**
 * Safety Entity inside the _Receiver, responsible for removing and checking the message Time Stamp and Sequence Number
 * @param safeMsg Message recovered by security entity that contains the sequence number and time stamp
 * @param senderID Sender identificator, also called label
 * @param timeStamp Time the message was sent in microseconds 
 * @param rRet SenderReturn object
 * @return Updated ReceiverReturn object (rRet)
 * */
ReceiverReturn entity_safety_rcv(std::string safeMsg, std::string senderID, long int timeStamp, ReceiverReturn rRet)
{
    int i, pos, pos2, seqNumber = 0;
    long int msgTimeStamp = 0;
    std::string temp1;
    /**
     * Gets the position from the separators '|' inside the string:
     * pos: Stores the '|' position separating the TimeStamp from the rest,
     * temp1: Stores the string starting on position till the end,
     * pos2: Stores the '|' position separating Plain text from sequence number
     * */

    pos = safeMsg.find(Rcv.delimiter);             
    temp1 = safeMsg.substr(pos+Rcv.delimiter.length());    
    pos2 = temp1.find(Rcv.delimiter);   

    /**
     * Spliting the received string to get the time stamp, message received from security (safeMsg) and sequence ID 
     * */
    msgTimeStamp = std::stol(safeMsg.substr(0,pos));
    safeMsg = temp1.substr(0, pos2);

    try{
        seqNumber = std::stol(temp1.substr(pos2+Rcv.delimiter.length()));
    }
    catch (std::invalid_argument const& ex)
    {
        std::cout << "[Warning] Invalid message syntax. You must not send the delimiter inside your message." << std::endl;
        safeMsg = "invalid message syntax";
        msgTimeStamp = -1;
        seqNumber = -1;
        return rRet;
        // throw std::invalid_argument("Invalid syntax. You must not send the delimiter inside your message");
    }               

   

    // std::cout << "msg: " << safeMsg << std::endl;
    // std::cout << "arriving time stamp: " << msgTimeStamp << std::endl;
    // std::cout << "seq number: " << seqNumber << std::endl;
        
    /*  Check if the table is not empty and if status is OK */
    if((numConnect != EMPTY_TABLE) && (tableStatus == OK)){    

        /* ------------------ Evaluation Purporse Only ------------------ */
        if(writeDelay) 
            logDelay.open("delays.csv", std::ios::out | std::ios::app);
        if(writeError) 
            logError.open("logErrors.csv", std::ios::out | std::ios::app);  
        /* ----------------------- Evaluation End ----------------------- */


        /**
         * Goes through each element of the table looking for the Sender ID: 
         * IF it finds the Sender ID inside the array, THEN replace the data and timeStamp and increment sequence number by 1
         * Here message is replaced, thus the number of connections will not change
         * */
        for(i=0; i<numConnect; i++){               
            if(rRet.table[i].senderID == senderID){
                // std::cout << "\nConexion found, replacing the data inside the position "<< i 
                    // << " with new packet info... " <<std::endl;

                /**
                 * Check conditions for the sequence number integrity:
                 * @if it is sequential, status: 0 -> The message is OK 
                 * @if it is zero, status: 1 -> The message was duplicated
                 * @if less than zero, status: 2 -> The message has a wrong sequence ID (messages may have been lost)
                 * @if Bigger than zero, status: 3 -> The message is out-of-order
                 * */
                if ((seqNumber-rRet.table[i].seqNumber) == OK ){    
                    //std::cout << "The sequence number is OK (flag = 0), continue..." << std::endl;
                    rRet.table[i].status = sts_OK;

                }else if((seqNumber-rRet.table[i].seqNumber) == 0){   
                    // std::cout << "\n!!! The message is a duplication, setting status flag for DUPLICATED (status = 1) !!!! " << std::endl;
                    rRet.table[i].status = sts_DUP;
                
                }else if((seqNumber-rRet.table[i].seqNumber) < 0){ 
                    // std::cout << " \n!!! Lost messages, setting status flag for LOST (status = 2) !!!" << std::endl;
                    rRet.table[i].status = sts_wrongSEQ;
                }else {  
                    // std::cout << " \n!!! There is a message out of sequence, setting status flag for OUT-OF-ORDER (status = 3) !!!" << std::endl;
                    rRet.table[i].status = sts_lostMSG;
                }

                /**
                 * @if status is neither OUT-OF-ORDER nor DUPLICATED, calculate delay, update table and message
                 * */
                if(rRet.table[i].status != sts_wrongSEQ && rRet.table[i].status != sts_DUP){

                    
                    rRet.table[i].delayRcv = timeStamp - msgTimeStamp; /* Calculate the delay between sent message and received message  */
                    rRet.table[i].delaySnd = msgTimeStamp - rRet.table[i].timeStamp; /*  Calculate inter-message delay  */
                    rRet.table[i].data = safeMsg;
                    rRet.table[i].seqNumber = seqNumber;
                    rRet.table[i].timeStamp = msgTimeStamp; 

                    /** 
                     * Check conditions for inter-message delay and sent-received delay
                     * @if inter-message delay is bigger than INTER_MSG_DELAY_MAX, status: 4 
                     * @if sent-received delay is bigger than SENT_RCV_DELAY_MAX, status: 5 
                     * */
                    if (rRet.table[i].delaySnd > INTER_MSG_DELAY_MAX){ 
                        //std::cout << "\n!!! There is a big delay between the messages, setting status flag for delay between arriving messages (status = 4) !!!" << std::endl
                        if(writeError)
                            logError  << "Message " << rRet.table[i].seqNumber << ", " << "Status: " << sts_delaySnd << ", " << std::endl; 

                    }
                    if (rRet.table[i].delayRcv > SENT_RCV_DELAY_MAX){ 
                        //std::cout << "\n!!! The message's sent time is too different from the message's received time, please check the connection (status = 5) !!!" << std::endl;
                        if(writeError)
                            logError  << "Message " << rRet.table[i].seqNumber << ", " << "Status: " << sts_delayRcv << ", " << std::endl;  

                    }
                }
   
                if(writeError)
                    logError  << "Message " << seqNumber << ", " << "Status: " << rRet.table[i].status << ", " << std::endl;  
                if(writeDelay)
                    logDelay  << "Delay_" << rRet.table[i].seqNumber << ", " << rRet.table[i].delaySnd << std::endl; 
                    // logDelay  << "Delay_" << rRet.table[i].seqNumber << ", " << rRet.table[i].delaySnd << ", " << rRet.table[i].delayRcv << std:endl; 

                rRet.plainText = rRet.table[i].data;
                tableStatus = REPLACE_MSG; 
            }  
        }
        
        /**
         * IF table status did not change (status == OK):
         * The sender doesn't exists inside the table yet, THEN create new connection
         * New message/connection is created and the number of connections increases by 1
         * */
        if(tableStatus == OK){
            // std::cout << "\n<< Adding a new packet inside the table in position [" << numConnect << "] >>" << std::endl;

            /**
             * Check conditions for the sequence number integrity:
             * @if it is sequential, status: 0 -> The message is OK 
             * @if it is zero, status: 1 -> The message was duplicated
             * @if less than zero, status: 2 -> The message is out-of-order
             * @if neither one nor zero, status: 3 -> The message has a wrong sequence ID (messages may have been lost)
             * */
            rRet.table[numConnect].seqNumber = 0;
            if ((seqNumber-rRet.table[numConnect].seqNumber) == OK )
            {
                //std::cout << "The sequence ID is OK (status = 0), continue..." << std::endl;
                rRet.table[numConnect].status = sts_OK; 
            }
            else if((seqNumber-rRet.table[numConnect].seqNumber) != OK)
            {  
                // std::cout << " \n!!! Lost messages, setting status flag for LOST (status = 3) !!!" << std::endl;
                rRet.table[numConnect].status = sts_lostMSG;
            }         

            rRet.table[numConnect].delayRcv = timeStamp - msgTimeStamp; 
            rRet.table[numConnect].delaySnd = 0;
            rRet.table[numConnect].data = safeMsg;
            rRet.table[numConnect].senderID = senderID;        
            rRet.table[numConnect].seqNumber = seqNumber;   
            rRet.table[numConnect].timeStamp = msgTimeStamp;  

            if (rRet.table[numConnect].delayRcv > SENT_RCV_DELAY_MAX){ 
                // std::cout << "\n!!! The message's send time is too different from the message's received time, please check the connection (flag = 5) !!!" << std::endl;
                if(writeError)
                    logError  << "Message " << rRet.table[numConnect].seqNumber << ", " << "Status: " << sts_delayRcv << ", " << std::endl;  

            }

            if(writeError)
                logError  << "Message " << seqNumber << ", " << "Status: " << rRet.table[numConnect].status << ", " << std::endl;  
            if(writeDelay)
                logDelay  << "Delay_" << rRet.table[numConnect].seqNumber << ", " << rRet.table[numConnect].delaySnd << std::endl; 
                // logDelay  << "Delay_" << rRet.table[numConnect].seqNumber << ", " << rRet.table[numConnect].delaySnd << ", " << rRet.table[numConnect].delayRcv << std::endl; 

            rRet.plainText = rRet.table[numConnect].data;

            tableStatus = NEW_MSG;
            numConnect++;    
            rRet.table->size = numConnect;            
        }

    }

    /**
     * IF table is empty, THEN create first connection of the table
     * Set number of connections and the sequence number to 1 
     * */
    else if(numConnect == EMPTY_TABLE){
        
        //std::cout << "\nMy Receiver table is empty, creating new packet... " << std::endl;
        rRet.table[0].data = safeMsg;
        rRet.table[0].senderID = senderID;
        rRet.table[0].seqNumber = seqNumber;
        rRet.table[0].timeStamp = msgTimeStamp;
        
        numConnect = 1;
        rRet.table->size = 1;
                  
        rRet.plainText = rRet.table[0].data;

        if(writeDelay)
            logDelay  << "Delay_" << rRet.table[0].seqNumber << ", " << 0 << std::endl; 
            // logDelay  << "Delay_" << rRet.table[0].seqNumber << ", " << rRet.table[0].delaySnd << ", " << rRet.table[i].delayRcv << std::endl; 

    }

    tableStatus = OK;

    /* ------------------ Evaluation Purporse Only ------------------ */
    if(writeDelay)
        logDelay.close();
    if(writeError)
        logError.close();  
    /* ----------------------- Evaluation End ----------------------- */
    
    return rRet;
}

/**
 * WSSL rcv function is responsible for calling the safety and security entities
 * @param wsslMsg Message received from application
 * @param senderID Sender identificator, also called label
 * @param path Path name of the Sender identity
 * @param timeStamp Time the message was sent in microseconds 
 * @param sRet SenderReturn object
 * @return sRet Updated SenderReturn object
 * */
ReceiverReturn wssl_rcv_msg(std::string wsslMsg, std::string senderID, std::string path, long int timeStamp,  ReceiverReturn rRet){
    
    rRet = entity_security_rcv(wsslMsg, senderID, path, rRet);
    if(rRet.plainText == "error"){
        if(writeError){
            logError.open("logErrors.csv", std::ios::out | std::ios::app);
            logError  << "Security error!" << std::endl; 
            logError.close();
        }
        return rRet;
    }else{
        rRet = entity_safety_rcv(rRet.plainText, senderID, timeStamp, rRet);
        return rRet;
    } 
}

/**
 * Recover senderID and wsslMsg size from the message received from sender, remove the appended info and save the signed message
 * @param wsslMsg Signed message received from the WSSL Sender
 * @param senderID Sender identificator, also called label
 * @param rRet ReceiverReturn object type containing the message and the receiver table
 * @return The identification of the Sender (label)
 * */
std::string handle_msg(std::string wsslMsg, std::string senderID, ReceiverReturn &rRet){
    
    try{
        senderID = wsslMsg.substr(SIZE_MSG, Rcv.sizeLabel);
        // std::cout << senderID << std::endl;
        int msgSize = wsslMsg.length();
        rRet.plainText = wsslMsg.substr(SIZE_MSG + Rcv.sizeLabel, msgSize);
    }
    catch (std::out_of_range const& ex)
    {
        std::cout << "[Warning] Invalid message syntax" << std::endl;
        rRet.plainText = "error";
        return rRet.plainText;
        // throw std::invalid_argument("Invalid syntax. You must not send the delimiter inside your message");
    }               
  
    return senderID;
}

ReceiverReturn LibWssl::init_wssl_rcv(std::string wsslMsg, std::string path, ReceiverReturn rRet){

    long int timeStamp = Rcv.get_time_stamp_micro();

    delete_old_connexions_rcv(rRet);

    std::string senderID;
    senderID = handle_msg(wsslMsg, senderID, rRet);

    // std::cout << "\nReceiveing from handle:" << rRet.plainText << std::endl;
    // std::cout << "\nSender:" << senderID << std::endl;
    if (senderID == "error"){
        return rRet;
    }else{
        rRet = wssl_rcv_msg(rRet.plainText, senderID, path, timeStamp, rRet);
        return rRet;
    }

}

void LibWssl::delete_old_connexions_rcv(ReceiverReturn rRet)
{
    //Delete connection if has passed 
    float sec = 1000000;
    long int timeNow = Rcv.get_time_stamp_micro();
    
    for (int i = 0; i < numConnect; i++)
    {
        if( (timeNow - rRet.table[i].timeStamp) / sec >= LIM_TIME_SEC){
            for (int j = i; j< numConnect-1; j++){
                rRet.table[j] = rRet.table[j+1];
            }

            std::cout << "[Debug] Deleted message in position [" << i << "]" << std::endl;
            numConnect --;
            rRet.table->size = numConnect;
            i--;
        }
    }
}



