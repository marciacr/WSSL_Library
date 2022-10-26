#include "src/lib_wssl.h"
#include <iostream>
#include <mosquitto.h>
#include <chrono> //used for testing purpose

#define ASCII_TO_DEC 48 	// Transformation from ASCII to Decimal
#define SIZE_MSG 3 			// Reserved size to store the size of the signed message
#define SIZE_SENDER_NAME 4 	// Reserved size to store the sender name of the received message

using namespace std;

int nmsg = 0; // Number of received messages
struct wssl_rcv_return rRet;

/* ------------------ Testing Purporse Only ------------------ */
#define NUM_MSG 20 //define number of messages you want to calculate the delay of the receiving messages
long int time_last, time_first, rcv_time;
long int sget_timeStamp();

void on_connect(struct mosquitto *mosq, void *obj, int rc)
{
	//cout << "We are connected to the ID: " << *(int*)obj << endl << endl;
	if(rc) {
		cout << "Error on connect with result code: " << rc << endl;
		exit(-1);
	}
	mosquitto_subscribe(mosq, NULL, "test/wssl", 0);
}

void on_message(struct mosquitto *mosq, void *obj, const struct mosquitto_message *msg) {
	/* ------------------- DELAY CALC -------------------*/
	if (nmsg==0){
		time_first = sget_timeStamp();
	}else if (nmsg==NUM_MSG-1) {
		time_last = sget_timeStamp();
    }
	rcv_time = time_last - time_first;
	/* ------------------- DELAY CALC -------------------*/

	string size_msg, sender_size_name, id_sender;
	unsigned char const* bytes = static_cast<unsigned char const*>(msg->payload);

	for(int i = 0 ; i < SIZE_MSG ; ++i){
		size_msg = size_msg + to_string(static_cast<unsigned int>(bytes[i]) - ASCII_TO_DEC);
	}
	int msize = stoi(size_msg);

    string wssl_msg(static_cast<const char*>(msg->payload), SIZE_MSG + SIZE_SENDER_NAME + msize);
	//cout << "\nReceiveing from sender:" << wssl_msg << endl;

	id_sender = wssl_msg.substr(SIZE_MSG, SIZE_SENDER_NAME);
	wssl_msg = wssl_msg.substr(SIZE_MSG + SIZE_SENDER_NAME, msize);

	/* ---------- ONLY SAFETY TEST ---------*/
	// string wssl_msg(static_cast<const char*>(msg->payload));
	// string sender = "PK01";

	/* ----------- ONLY MQTT TEST ----------*/
	// string wssl_msg(static_cast<const char*>(msg->payload));
	// cout << "MQTT message:" << wssl_msg << endl;

	// cout << "Treated message: " << wssl_msg << endl;
	// cout << "Size of received msg: " << msize << endl;
	// cout << "Sender ID: " << id_sender << endl;
	
    rRet = init_wssl_rcv(wssl_msg, id_sender, rRet);

	if(rRet.plain_text == "error"){
		cout << "Security error!" << endl;
	}else{
		int size_rcv = rRet.table->size_array;
		//cout << "\nThe array of struct in Receiver has " << size_rcv << " connections"<< endl << endl;

		// Print Receiver table with all existing connections 
		cout << "\ntimeStamp(us) | MESSAGE | Seq. Number | Status | delaySender(us) | delayReceiver(us)" << endl;
		for(int i=0; i<size_rcv; i++){
			cout << rRet.table[i].timeStamp << " | ";
			cout << rRet.table[i].data << " | ";
			cout << rRet.table[i].seq_number << " | ";
			cout << rRet.table[i].status << " | ";
			cout << rRet.table[i].delay_send << " | ";
			cout << rRet.table[i].delay_rcv << endl;
		}
		cout << endl;
	}

	nmsg++;

	//Testing number of messages received
    cout << "Received messages: " << nmsg << endl; 
	/* ------------------ DELAY CALC ------------------*/
	if (nmsg == NUM_MSG)
	{
		cout << "Receive time for "<< NUM_MSG << " messages: " << rcv_time << " ms" << endl;
		nmsg =0;
	} 
	/* ------------------ DELAY CALC ------------------*/
}

int main(){

	rRet.table = (packet_rcv *)malloc(sizeof(packet_rcv)*500);
	if(rRet.table == NULL)
    {
        cout << "malloc failed!" << endl;   //could also call perror here
        free(rRet.table);
        rRet.table = NULL; 
    }

    int rc, id = 10;
	struct mosquitto *mosq;
	mosquitto_lib_init();	

	mosq = mosquitto_new("subscribe-test", true, &id);
    mosquitto_int_option(mosq, MOSQ_OPT_RECEIVE_MAXIMUM, 65535);
	mosquitto_connect_callback_set(mosq, on_connect);
	mosquitto_message_callback_set(mosq, on_message);

	rc = mosquitto_connect(mosq, "localhost", 1883, 10);
	if(rc) {
		cout << "Could not connect to Broker with return code " << rc << endl;
		return -1;
	}
	
	mosquitto_loop_start(mosq);
	cout << "Press Enter to quit..." << endl;
	getchar();
	mosquitto_loop_stop(mosq, true);

	mosquitto_disconnect(mosq);
	mosquitto_destroy(mosq);
	mosquitto_lib_cleanup();

	return 0;
}

/* ---------------- Function responsible for calculating the time used to calculate delay (testing purpose only) ---------------- */
long int sget_timeStamp(){
    long int timeStamp = static_cast<long int>
        (chrono::duration_cast<chrono::milliseconds>(chrono::high_resolution_clock::now().time_since_epoch()).count());
    return timeStamp;
}