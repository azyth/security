#ifndef srctable_H
#define srctable_H


#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <arpa/inet.h>

typedef struct hashtable hashtable_t;

enum table_type {
    FLOW,
    SRC,
    PORT
} table_type;

enum packet_type{
    SYN,
    ACK,
    SYN_ACK,
    FIN,
    FIN_ACK,
    XMAS,
    NUL,
    RST,
    RST_ACK,
    OTR
} packet_type;

enum sender{
    CLIENT,
    SERVER
} sender;

enum status_type {
    CONNECTING,
    OPEN,
    CLOSING,
    CLOSED
} status_type;

enum port_scan_type {
    NONE,
    SYN_SCAN,
    FIN_SCAN,
    XMAS_SCAN,
    NUL_SCAN,
    CONN_SCAN,
    HORIZ_SCAN,
    SEQ_SCAN
} port_scan_type;

enum dest {
    DIFFERENT,
    SAME_IP,
    SAME_PORT,
    SAME_IP_PORT
} dest;

typedef struct packet{
    enum packet_type type;
    uint32_t four_tuple[4];
    struct timeval timestamp;
} packet_t; 

  typedef struct connection {
    int key;
    int num_packets;
    int client_packets;
    enum status_type status;
    uint32_t four_tuple[4];
    int client_fin;  
    int server_fin;
    //used to keep track of the three way handshake. 
    enum packet_type last_packet_type;
    enum sender last_packet_from;
    struct timeval last_packet_time;
} connection_t;

//holds relevant data fro each connection , not sure how much of this is neccesary.
typedef struct source {
    int ip;
    int dest_ip;
    enum port_scan_type portscanner;
    int total_packets;
    int num_comp_conn; //complete connection
    int num_syns;
    int num_fins;
    int num_xmas;
    int num_nul;
    int num_rsts;
    int num_sequential_ports;
    int num_horizontal_scans;
    int last_dest_port;
    int last_dest_ip;

    enum packet_type last_type;
    struct timeval first_packet_time;  
    struct timeval last_packet_time;

    hashtable_t* dest_ports;

} source_t;


typedef struct destination {
    int num_packets;
    uint32_t three_tuple[3];
    struct timeval first_packet_time;  
    struct timeval last_packet_time;    
} destination_t;

////////////////// LINKED LIST  ///////////////////////

typedef struct list {
    struct list* next;
    struct list* prev;
    connection_t* connection;
    source_t* source;
    destination_t* destination;
} list_t;

////////////////// srctable //////////////////////////

typedef struct hashtable{
    unsigned int size;
    int table_type;
    int num_buckets;
    list_t** table;
} hashtable_t;





hashtable_t* create_table(int num_buckets, int table_type);
unsigned int hash_key(uint32_t four_tuple[], hashtable_t* table);

list_t* lookup(uint32_t four_tuple[], hashtable_t* table) ;
int compare_four_tuple(uint32_t p[], uint32_t connection[]);
int compare_two_tuple(uint32_t p[], uint32_t connection[]);
void update_connection(packet_t* p, list_t* list, hashtable_t* flowtable, hashtable_t* sourcetable);
void new_connection(packet_t* p, hashtable_t* flowtable);
void update_source(packet_t* p, list_t* list, hashtable_t* hashtable);
void new_source(packet_t* p, hashtable_t* table);
void update_destination(packet_t* p, hashtable_t* desttable);
void new_destination(packet_t* p, hashtable_t* desttable);
void free_table(hashtable_t* table);
void remove_flow(list_t* connection, hashtable_t* flowtable, hashtable_t* sourcetable);
void remove_connection(list_t* connection, hashtable_t* hashtable);
void remove_src_connection(list_t* list, hashtable_t* hashtable, int i);
void decrement_connection(list_t* list, hashtable_t* sourcetable);
void receive_packet(packet_t* p, hashtable_t* flowtable, hashtable_t* sourcetable);
void print_connection(list_t* list);

#endif


