#include "table.h"

/*************************
* Portscanning hashtable * 
**************************/


unsigned int hash_key(uint32_t four_tuple[], hashtable_t* hashtable) {
    if (hashtable->table_type == FLOW) {
        unsigned int xor = four_tuple[0] ^ four_tuple[2] ^ four_tuple[1] ^ four_tuple[3];
        return xor % hashtable->num_buckets; 
    }
    else if (hashtable->table_type == SRC) {
        return four_tuple[0] % hashtable->num_buckets;
    }
    else { //PORT table
        return (four_tuple[0] ^ four_tuple[2] ^ four_tuple[3]) % hashtable->num_buckets;
    }
}
/*
 * creates hsahtable of size XXX 
 * RETURNS: ptr to hashtable
 */
hashtable_t* create_table(int num_buckets, int table_type){

    if (num_buckets < 1) return NULL;
  
    hashtable_t* hashtable;
  //allocate space for hashtable  
    if ((hashtable = malloc(sizeof(hashtable_t))) == NULL) { 
        printf("%s\n", "hashtable malloc error.");
        return NULL;
    }
    if ((hashtable->table = malloc(sizeof(list_t*) * num_buckets)) == NULL) {
        printf("%s\n", "hashtable table malloc error.");
        return NULL;
    }
    hashtable->size = 0;
    int i;
    for (i = 0; i < num_buckets; ++i) {
        hashtable->table[i] = NULL;
    }
    hashtable->num_buckets = num_buckets; 
    hashtable->table_type = table_type;
  
    return hashtable;
}

void receive_packet(packet_t* p, hashtable_t* flowtable, hashtable_t* sourcetable) {
    list_t* list = lookup(p->four_tuple, flowtable);
    
    //add to flowtable
    if (list == NULL && p->type == SYN) {
        new_connection(p, flowtable);
    }
    else if (list != NULL) {
        update_connection(p, list, flowtable, sourcetable);
    }
    
    //add to srctable
    list = lookup(p->four_tuple, sourcetable);
    if (list == NULL && (p->type == SYN  || p->type == FIN || p->type == XMAS || 
                         p->type == NUL  || p->type == RST )) {
        new_source(p, sourcetable);
    }
    else if (list != NULL) {
        update_source(p, list, sourcetable);
    }
}

list_t* lookup(uint32_t four_tuple[], hashtable_t* hashtable) {
    unsigned int hashval = hash_key(four_tuple, hashtable);
    list_t* list = hashtable->table[hashval]; //chained list at bucket
    while(list != NULL) {
        switch(hashtable->table_type){

        case SRC :
            if (four_tuple[0] == list->source->ip) return list;
            break;

        case FLOW :
            if (compare_four_tuple(four_tuple, list->connection->four_tuple) == 0) return list;
            break;
      
        case PORT:
            if (compare_two_tuple(four_tuple, list->destination->three_tuple) == 0) return list;
            break;
    }
    list = list->next;
  }
  return NULL; //no match
}
int compare_two_tuple(uint32_t p[], uint32_t destination[]) {
    if (p[2] == destination[1] && p[3] == destination[2]) 
        return 0;
    return 1; //2 tuples (destination ip/port) not the same
}

int compare_four_tuple(uint32_t p[], uint32_t connection[]) {
  //if packet going from client->server
    if (p[0] == connection[0] &&
        p[1] == connection[1] &&
        p[2] == connection[2] && 
        p[3] == connection[3]) 
        return 0;
  //if packet going from server->client
    if (p[0] == connection[2] && 
        p[1] == connection[3] && 
        p[2] == connection[0] && 
        p[3] == connection[1]) 
        return 0;
    return 1; //4 tuples not the same
}

void new_connection(packet_t* p, hashtable_t* table) {
    list_t* new_list;

    if ((p->type != SYN) || (lookup(p->four_tuple, table) != NULL)) return;

    if ((new_list = malloc(sizeof(list_t)) ) == NULL) {
        printf("%s\n", "new_list malloc error.");
        return;
    }
    new_list->next = NULL;
    new_list->prev = NULL;
 
    //initialize new connection
    new_list->connection = malloc(sizeof(connection_t));

    new_list->connection->four_tuple[0] = p->four_tuple[0];
    new_list->connection->four_tuple[1] = p->four_tuple[1];
    new_list->connection->four_tuple[2] = p->four_tuple[2];
    new_list->connection->four_tuple[3] = p->four_tuple[3];

    new_list->connection->status = CONNECTING;
    new_list->connection->num_packets = 1;
    new_list->connection->client_fin = 0;
    new_list->connection->server_fin = 0;
    new_list->connection->last_packet_type = SYN;
    new_list->connection->last_packet_from = CLIENT;
    new_list->connection->last_packet_time = p->timestamp;
    new_list->connection->client_packets = 1;

    //add connection to beginning of current hashval list
    unsigned int hashval = hash_key(p->four_tuple, table);
    if (table->table[hashval] != NULL){
        table->table[hashval]->prev = new_list;
    }
    new_list->next = table->table[hashval];
    new_list->prev = NULL;
    table->table[hashval] = new_list;
}

void update_connection(packet_t* p, list_t* list, hashtable_t* flowtable, hashtable_t* sourcetable) {
// ++(list->connection->num_packets);
    list->connection->last_packet_time = p->timestamp;

    //if from the client increment client packets
    if (p->four_tuple[0] == list->connection->four_tuple[0]){
        list->connection->client_packets++;
    }
    //if SYN_ACK from server after receiving syn has from client
    if (p->type == SYN_ACK && list->connection->last_packet_type == SYN
        && p->four_tuple[2] == list->connection->four_tuple[0]) {
            list->connection->last_packet_type = SYN_ACK;
            list->connection->last_packet_from = SERVER;
    }
  
  //if ack sent from client in response to SYN_ACK
    else if (p->type == ACK && list->connection->last_packet_type == SYN_ACK
        && p->four_tuple[2] == list->connection->four_tuple[2]) {
            list->connection->last_packet_type = ACK;
            list->connection->last_packet_from = CLIENT;
            list->connection->status = OPEN;
    }
  //if fin from client->serv
    else if ((p->type == FIN || p->type == FIN_ACK) && p->four_tuple[2] == list->connection->four_tuple[2]) {
        list->connection->status = CLOSING;
        list->connection->client_fin = 1;
        if (list->connection->server_fin == 1)
            list->connection->status = CLOSED;
    }
  //if fin from serv after client already sent fin
    else if ((p->type == FIN || p->type == FIN_ACK) && p->four_tuple[2] == list->connection->four_tuple[0]) {
        list->connection->status = CLOSING;
        list->connection->server_fin = 1;
        if (list->connection->client_fin == 1)
            list->connection->status = CLOSED;
    }
  //if its a regular packet and status == open or closing
    else if (list->connection->status != CLOSED) {
        list->connection->last_packet_type = p->type;
    }

    if (list->connection->status == CLOSED) {
        remove_flow(list, flowtable, sourcetable);
    }
}

void new_source(packet_t* p, hashtable_t* srctable) {
    list_t* new_list;

    if (lookup(p->four_tuple, srctable) != NULL) return;

    if ((new_list = malloc(sizeof(list_t)) ) == NULL) {
        printf("%s\n", "new_list malloc error.");
        return;
    }
    new_list->next = NULL;
    new_list->prev = NULL;
 
    //initialize new source
    new_list->source = malloc(sizeof(source_t));
    new_list->source->first_packet_time = p->timestamp;
    new_list->source->last_packet_time = p->timestamp;

    new_list->source->ip = p->four_tuple[0];
    new_list->source->portscanner = NONE;
    new_list->source->total_packets = 1;
    new_list->source->num_comp_conn = 0;
    new_list->source->num_syns = 0;
    new_list->source->num_fins = 0;
    new_list->source->num_nul = 0;
    new_list->source->num_xmas = 0;
    new_list->source->num_rsts = 0;
    new_list->source->num_sequential_ports = 1;
    new_list->source->last_dest_ip = p->four_tuple[2];  
    new_list->source->last_dest_port = p->four_tuple[3];
    new_list->source->num_horizontal_scans = 0;
    new_list->source->last_type = p->type;
    new_list->source->dest_ports = create_table(1024, PORT);
    new_destination(p, new_list->source->dest_ports);

    if (p->type == SYN)  new_list->source->num_syns = 1;
    if (p->type == FIN)  new_list->source->num_fins = 1;
    if (p->type == NUL)  new_list->source->num_nul = 1;
    if (p->type == XMAS) new_list->source->num_xmas = 1;
    if (p->type == RST)  new_list->source->num_rsts = 1;


    //add source to beginning of current hashval list
    unsigned int hashval = hash_key(p->four_tuple, srctable);
    if (srctable->table[hashval] != NULL){
        srctable->table[hashval]->prev = new_list;
    }
    new_list->next = srctable->table[hashval];
    new_list->prev = NULL;
    srctable->table[hashval] = new_list;
}



enum dest check_destination(packet_t* p, list_t* list) {
    if (p->four_tuple[2] == list->source->last_dest_ip && p->four_tuple[3] == list->source->last_dest_port)
        return SAME_IP_PORT;
    if (p->four_tuple[2] == list->source->last_dest_ip && p->four_tuple[3] != list->source->last_dest_port)
        return SAME_IP;
    if (p->four_tuple[2] != list->source->last_dest_ip && p->four_tuple[3] == list->source->last_dest_port)
        return SAME_PORT;  
    else
        return DIFFERENT;
}

void update_source(packet_t* p, list_t* list, hashtable_t* srctable) {
    ++(list->source->total_packets);

    update_destination(p, list->source->dest_ports);
    
    //it's just trying to send a syn to the same ip/port over and over so it's not a scan
    if (check_destination(p, list) == SAME_IP_PORT && p->type == list->source->last_type) return;

    list->source->last_packet_time = p->timestamp;    
    double ratio;


    // Test to see if ratio of syns/total packets is too high
    if (p->type == SYN) {
        ++(list->source->num_syns);
        ratio = (double)list->source->num_syns/list->source->total_packets;
        if (list->source->num_syns >= 5 && ratio >= .6) {
            if (list->source->portscanner != CONN_SCAN) {
                list->source->portscanner = SYN_SCAN;
                list->source->dest_ip = p->four_tuple[2];
            }
        }
    }

    // Test to see if ratio of fins/total packets is too high
    if (p->type == FIN) {
        ++(list->source->num_fins);
        ratio = (double)list->source->num_fins/list->source->total_packets;
        if (list->source->num_fins >= 5 && ratio > .6) {
            list->source->portscanner = FIN_SCAN;
            list->source->dest_ip = p->four_tuple[2];
        }
    }

    if (p->type == XMAS) {
        ++(list->source->num_xmas);
        ratio = (double)list->source->num_xmas/list->source->total_packets;
        if (list->source->num_xmas >= 5 && ratio > .75) {
        list->source->portscanner = XMAS_SCAN;
        list->source->dest_ip = p->four_tuple[2];
        }
    }
    if (p->type == NUL) {
        ++(list->source->num_nul);
        if (list->source->num_nul >= 1) {
        list->source->portscanner = NUL_SCAN;
        list->source->dest_ip = p->four_tuple[2];
        }
    }  

    if (p->type == RST) {
        ++(list->source->num_rsts);
        if (list->source->num_rsts > 100) {
        list->source->portscanner = CONN_SCAN;
        list->source->dest_ip = p->four_tuple[2];
        }    
    }

  //check for sequential scans regardless of flags
    if (check_destination(p,list) == SAME_IP && (p->four_tuple[3] == list->source->last_dest_port + 1 || p->four_tuple[3] == list->source->last_dest_port - 1)) {
        ++(list->source->num_sequential_ports);
        if (list->source->num_sequential_ports >=5) {
            list->source->portscanner = SEQ_SCAN;
        }
    }

    //check for horizontal scans
    if (check_destination(p, list) == SAME_PORT) {
        ++list->source->num_horizontal_scans;
        if (list->source->num_horizontal_scans >=5) {
            list->source->portscanner = HORIZ_SCAN;
        }
    }

    list->source->last_dest_port = p->four_tuple[3];
    list->source->last_dest_ip = p->four_tuple[2];
}

void new_destination(packet_t* p, hashtable_t* desttable) {
    list_t* new_list;

    //make new destination entry in desttable
    if (lookup(p->four_tuple, desttable) != NULL) return;

    if ((new_list = malloc(sizeof(list_t)) ) == NULL) {
        printf("%s\n", "new_list malloc error.");
        return;
     }
    new_list->next = NULL;
    new_list->prev = NULL;
 
    //initialize new destination
    if ((new_list->destination = malloc(sizeof(destination_t)) ) == NULL) {
        printf("%s\n", "destination malloc error.");
        return;
    }


    new_list->destination->num_packets = 1;

    new_list->destination->first_packet_time = p->timestamp;
    new_list->destination->last_packet_time = p->timestamp;  

    new_list->destination->three_tuple[0] = p->four_tuple[0];
    new_list->destination->three_tuple[1] = p->four_tuple[2];
    new_list->destination->three_tuple[2] = p->four_tuple[3];

    //add source to beginning of current hashval list
    unsigned int hashval = hash_key(p->four_tuple, desttable);
    if (desttable->table[hashval] != NULL) {
        desttable->table[hashval]->prev = new_list;
    }
    new_list->next = desttable->table[hashval];
    new_list->prev = NULL;
    desttable->table[hashval] = new_list;

    //update number of entries in desttable
    ++desttable->size;
}

void update_destination(packet_t* p, hashtable_t* desttable){
    list_t* list = lookup(p->four_tuple, desttable);

    if (list == NULL) {
        new_destination(p, desttable);
    }
    else {
        list->destination->num_packets++;
        list->destination->last_packet_time = p->timestamp;
    }
}

void remove_flow(list_t* list, hashtable_t* flowtable, hashtable_t* sourcetable){
    decrement_connection(list, sourcetable);
    remove_connection(list, flowtable);//do not print it out
	//free(list);
}

void decrement_connection(list_t* list, hashtable_t* sourcetable){
    //find index of src_ip in sourcetable
    list_t* srclist = lookup(list->connection->four_tuple, sourcetable);

    //reduce syn and fin by one for a legit connection. (possible more where in there)
    --srclist->source->num_syns;
    --srclist->source->num_fins;

    //add a total connections to source table and increment it here. 
    ++(srclist->source->num_comp_conn);
}

void remove_connection(list_t* list, hashtable_t* hashtable) {
    if (hashtable->table_type == FLOW) {

        if (list->prev != NULL) {
            list->prev->next = list->next;
        }
        else {
            unsigned int hashval = hash_key(list->connection->four_tuple, hashtable);
            hashtable->table[hashval] = list->next;
        }

        if (list->next != NULL) {
            list->next->prev = list->prev;
        }
        free(list->connection);
    }
    else if (table_type == SRC) {//type SRC
        if (list->prev != NULL) {
            list->prev->next = list->next;
        }
        else {
            uint32_t fake_four_tuple[4] = { list->source->ip, 0, 0, 0 };
            unsigned int hashval = hash_key(fake_four_tuple, hashtable);
            hashtable->table[hashval] = list->next;
        }

        if (list->next != NULL) {
            list->next->prev = list->prev;
        }
        if (list->source->dest_ports != NULL) {
			free_table(list->source->dest_ports);
		}
        free(list->source);
    }
    else if (table_type == PORT) { //type == PORT
        if (list->prev != NULL) {
            list->prev->next = list->next;
        }
        else {
            int srcip = list->destination->three_tuple[0];
            int destip = list->destination->three_tuple[1];
            int destport = list->destination->three_tuple[2];
            uint32_t fake_four_tuple[4] = { srcip, 0, destip, destport };
            unsigned int hashval = hash_key(fake_four_tuple, hashtable);
            hashtable->table[hashval] = list->next;
        }

        if (list->next != NULL) {
            list->next->prev = list->prev;
        }
        free(list->destination);
    }

    free(list);
}


void free_table(hashtable_t* hashtable){
    if (hashtable == NULL) return;

  //free each element in the hashtable's table
    int i;
   // int deallocate = 0;
    for (i = 0; i < hashtable->num_buckets; i++) {
        list_t* list;
        for (list = hashtable->table[i]; list != NULL; list = hashtable->table[i]) {
 			//list_t* l = hashtable->table[i];         
			remove_connection(hashtable->table[i], hashtable);
            //free(l);
        }
    }
    //free hashtable itself
    free(hashtable->table);
    free(hashtable);
}

void print_connection(list_t* list) {
    struct in_addr src_ip;
    struct in_addr dest_ip;
    src_ip.s_addr = list->connection->four_tuple[0];
    dest_ip.s_addr = list->connection->four_tuple[2];


    int src_port = list->connection->four_tuple[1];
    int dest_port = list->connection->four_tuple[3];
    int num_packets = list->connection->num_packets;

    char ts[64]; 
    time_t pkt_time = list->connection->last_packet_time.tv_sec; 
    struct tm* pkt_time_struc = localtime(&pkt_time);
    strftime(ts, sizeof(ts), "%H:%M:%S", pkt_time_struc);
    //keep ts_usec vars and add %s to front of printf statement
    int us = (int)list->connection->last_packet_time.tv_usec;

    printf("%s.%06d Flow ", ts, us);
    printf("%s:%d ->", inet_ntoa(src_ip), ntohs(src_port));
    printf(" %s:%d second fin after %d packets\n", inet_ntoa(dest_ip), ntohs(dest_port), num_packets);
}

