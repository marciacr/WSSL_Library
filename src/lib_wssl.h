#include <string>

struct wssl_send_return
    {
        struct packet_send *table;
        std::string wssl_msg;
    };

struct wssl_rcv_return
    {
        struct packet_rcv *table;
        std::string plain_text;
    };

struct packet_send
    {
        std::string data;
        long int timeStamp;
        int seq_number;         // Sequence Number
        std::string dest;       // Message destination
        int size_array;
    };

/* Packet receive struct is a table array with NUM connections */
struct packet_rcv
    {
        std::string data;
        int status;             // Message Status: OK: 0, Duplication: 1, Wrong Sequence ID: 2, Lost Messages: 3, Warning delay send: 4,  Warning delay receive: 5
        long int delay_send;    // Delay send: delay between two messages from the same sender
        long int delay_rcv;     // Delay receive: delay between the Time Stamp of the arriving message and the time it was really received
        long int timeStamp;
        int seq_number;         // Sequence Number
        int size_array;
        std::string sender;     // Message sender
        
    };

/* Call init function from sender and receiver */
struct wssl_send_return init_wssl_send(std::string msg, std::string id_sender, std::string id_dest, struct wssl_send_return sRet);
struct wssl_rcv_return init_wssl_rcv(std::string wssl_msg, std::string id_sender, struct wssl_rcv_return rRet);

