#include "src/libwssl_class.h"
#include <iostream>
#include <mosquitto.h>

using namespace std;

/**
 * Start the library instantiating the class
*/
// WsslReceiver Receiver4;                          // initialization by default constructor
// WsslReceiver Receiver2(Receiver4);               // initialization by copy constructor
// WsslReceiver Receiver3 = Receiver2;             // Also initialization by copy constructor
WsslReceiver Receiver("rcvFile", "RCV1");   	// initialization by parametized constructor

/* ------------------ Evaluation Purporse Only ------------------ */
#define NUM_MSG 1
long int timeLast, timeFirst, rcvTime;
long int eval_get_time_stamp();
int nmsg = 0; // Number of received messages
/* ----------------------- Evaluation End ----------------------- */


void print_connection_table(WsslReceiver *Receiver){

	// Print Receiver table with all existing connections 
	cout << "timeStamp(us)" << "    " << Receiver->delimiter << "    " << "MESSAGE" << "    " << Receiver->delimiter << " " << "Seq. Number" << " " << Receiver->delimiter << " " << "Status" << " " << Receiver->delimiter << " " << "delaySender(us)" << endl;
	for(int i=0; i<Receiver->rRet.table->size; i++){
		cout << Receiver->rRet.table[i].timeStamp << " " << Receiver->delimiter << " ";
		cout << Receiver->rRet.table[i].data << "  " << Receiver->delimiter << "      ";
		cout << Receiver->rRet.table[i].seqNumber << "      " << Receiver->delimiter << "   ";
		cout << Receiver->rRet.table[i].status << "    " << Receiver->delimiter << "    ";
		cout << Receiver->rRet.table[i].delaySnd << endl;
	}
	cout << endl;
}

void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	cout << "We are connected to the ID: " << *(int*)obj << endl << endl;
	if(rc) {
		cout << "Error on connect with result code: " << rc << endl;
		exit(-1);
	}
	// Receiver = Receiver4;                           // Assignment by copy assignment operator

	mosquitto_subscribe(mosq, NULL, "wssl", 0);
}

void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg) {

	string wsslMsg(static_cast<const char*>(msg->payload), msg->payloadlen);
	//cout << "\nReceiveing from sender:" << wsslMsg << endl;
	// cout << "Size of received msg: " << msg->payloadlen << endl;

	/* ------------------ Evaluation Purporse Only ------------------ */
	if (nmsg==0){
		timeFirst = eval_get_time_stamp();
	}
	if (nmsg==NUM_MSG-1) {
		timeLast = eval_get_time_stamp();
    }
	rcvTime = timeLast - timeFirst;
	/* ----------------------- Evaluation End ----------------------- */

    // Receiver.get_my_public_key(Receiver.path); 				// Get your own public key in Sender.key
	// std::cout << "\nkey: " << Receiver.key << std::endl;
    // Receiver.create_my_id("rcvFile2", "rcvLabel2");      	// Create a new ID manually

    /**
     * Debug to add Sender identity to known identities inside the Receiver path
     * */
    CryptoIdentity *id = CryptoIdentity::load("senderFile");
    Receiver.add_known_identity(Receiver.path, "SND1", id->pk );

	/**
	 * Initialize library calling the receiver init function
	 * Application must treat the security error according to its necessity
	*/
    Receiver.rRet = Receiver.init_wssl_rcv(wsslMsg, Receiver.path, Receiver.rRet); 
	if(Receiver.rRet.plainText == "error"){	//
		cout << "Treat the error in security!" << endl;
	}else{
		print_connection_table(&Receiver);
	}

	/* ------------------ Evaluation Purporse Only ------------------ */
	nmsg++;
	//Testing number of messages received
    // cout << "Received messages: " << nmsg << endl; 
	if (nmsg == NUM_MSG)
	{
		cout << "Receiving time for "<< NUM_MSG << " messages: " << rcvTime << " ms" << endl;
		nmsg =0;
	} 
	/* ----------------------- Evaluation End ----------------------- */
}

int main(){

    int rc, id = 10;
	struct mosquitto *mosq;
	mosquitto_lib_init();	

	mosq = mosquitto_new("subscribe-test", true, &id);
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_message_callback_set(mosq, on_message);

	rc = mosquitto_connect(mosq, "192.168.1.162", 1885, 10);
	if(rc) {
		cout << "Could not connect to Broker with return code " << rc << endl;
		return -1;
	}
	
	mosquitto_loop_start(mosq);
	getchar();
	mosquitto_loop_stop(mosq, true);

	mosquitto_disconnect(mosq);
	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();

	return 0;
}

/* ------------------ Evaluation Purporse Only ------------------ */
long int eval_get_time_stamp(){
    long int timeStamp = static_cast<long int>
        (chrono::duration_cast<chrono::milliseconds>(chrono::high_resolution_clock::now().time_since_epoch()).count());
    return timeStamp;
}
/* ----------------------- Evaluation End ----------------------- */