
#include "table.h"
#include <stdio.h>
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


void print_entry(list_t* list) {
  	struct in_addr src_ip;
  	src_ip.s_addr = list->source->ip;
  	printf("Source IP      : %s\n", inet_ntoa(src_ip));

  	struct in_addr dest_ip;
  	dest_ip.s_addr = list->source->dest_ip;
  	printf("Destination IP : %s\n", inet_ntoa(dest_ip));

  	printf("Number of scans: %u\n", list->source->dest_ports->size);

  	printf("Scan type      : ");
  	switch(list->source->portscanner) {
  	case SYN_SCAN:
	  	printf("SYN scan, random order of ports\n");
  		break;
  	case FIN_SCAN:
  		printf("FIN scan, random order of ports\n");
  		break;
  	case XMAS_SCAN:
  		printf("XMAS scan, random order of ports\n");
  		break;
	case NUL_SCAN:
  		printf("Null scan, random order of ports\n");
  		break;
	case CONN_SCAN:
  		printf("TCP Connect scan, random order of ports\n");
    	break;
  	case HORIZ_SCAN:
  		printf("Horizonal scan, random order of ports\n");
  		break;

  	default:
  		break;
  	}


  	// char ts_start[64]; 
  	// time_t start_time = list->source->first_packet_time.tv_sec; //make first_packet_time field
  	// struct tm* start_time_struc = localtime(&start_time);
  	// strftime(ts_start, sizeof(ts_start), "%H:%M:%S", start_time_struc);
  	// int us_start = (int)list->source->first_packet_time.tv_usec;
  	// printf("First Packet: %s.%06d, ", ts_start, us_start); //I think this format may be off? check his comments for hw2

  	// char ts_end[64]; 
  	// time_t end_time = list->source->last_packet_time.tv_sec; 
  	// struct tm* end_time_struc = localtime(&end_time);
  	// strftime(ts_end, sizeof(ts_end), "%H:%M:%S", end_time_struc);
  	// int us_end = (int)list->source->last_packet_time.tv_usec;
  	// printf("Last Packet: %s.%06d, ", ts_end, us_end); //I think this format may be off? check his comments for hw2
  	
  	double sec_start = list->source->first_packet_time.tv_sec;
  	double usec_start = list->source->first_packet_time.tv_usec;
  	double sec_end = list->source->last_packet_time.tv_sec;
  	double usec_end = list->source->last_packet_time.tv_usec;

  	// double sec_diff = sec_end - sec_start;
  	// double usec_diff = (double_(usec_end - usec_start)/1000000);
  	//printf("%f\n", usec_start);
  	double total_start = sec_start + usec_start/1000000;
  	double total_end = sec_end + usec_end/1000000;
  	//printf("%f, %f\n", total_start, total_end);
  	double diff = total_end-total_start;
  	printf("Time taken     : %.4f\n", diff);
  	//printf("%f, %f, %f, %f\n", sec_start, usec_start, sec_end, usec_end);
  	//printf("start time: %.4f  end time: %.4f\n", (double)sec_end-sec_start, (double)usec_end-usec_start);

}

void print_portscanners(hashtable_t* hashtable) {
 	int i;
 	for (i = 0; i < hashtable->num_buckets; ++i) {
 		list_t* list;
 		for (list = hashtable->table[i]; list != NULL; list = list->next) {
    		if (list->source->portscanner != NONE) {
    			print_entry(list);
    			printf("\n");

    		}
    	}
  	}
}

// executive entrypoint
int main(int argc, char** argv) {

	// variable declarations here
	int counter;
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];	// contains verbose info about pcap failures
	struct pcap_pkthdr* info;
	const unsigned char* pkt;

	unsigned short proto;
	struct ethhdr* eth_hdr;
	struct iphdr* ip_header;
	struct tcphdr* tcp_hdr;

	// parse the command line
	if (argc < 2 || strcmp(argv[1], "-r") != 0 || argc < 3) {
		printf("usage: %s -r file_1 file_2 ... file_n\n", argv[0]);
		return 1;
	}

	hashtable_t* flowtable = create_table(65536, FLOW);
	hashtable_t* srctable = create_table(65536, SRC);
	
	// filenames are found in argv[2] to argv[argc-1]
	for (counter = 2; counter < argc; ++counter) {
		// open file for processing
		if ((handle = pcap_open_offline(argv[counter], errbuf)) == NULL) {
			printf("error loading [%s]. reason: [%s]\n", argv[counter], errbuf);
			return 1;
		}
		while (pcap_next_ex(handle, &info, &pkt) == 1) {
			//make sure packet can possibly be tcp
			if (info->len < sizeof(struct ethhdr*) + sizeof(struct iphdr*) + sizeof(struct tcphdr*)) { break; }            		
			
			//PARSE ETHERNET HEADER
			eth_hdr = (struct ethhdr*) pkt; // coerce cast
            proto = ntohs(eth_hdr->h_proto);
			if (proto != ETH_P_IP) { continue; }

			//PARSE IP HEADER
			ip_header = (struct iphdr*) (pkt+sizeof(struct ethhdr));
			if (ip_header->protocol != 6) { continue; }

			//PARSE TCP HEADER
			tcp_hdr = (struct tcphdr*) (pkt+sizeof(struct ethhdr)+sizeof(struct iphdr));

			//make the packet struct to send to hashtable		
			enum packet_type type = OTR;
			if (tcp_hdr->syn == 1 && 
				tcp_hdr->ack == 1) 						{ type = SYN_ACK; }

			else if (tcp_hdr->rst == 1 &&
					 tcp_hdr->ack ==1)					{ type = RST_ACK; }

			else if (tcp_hdr->rst == 1)					{ type = RST; }


			else if (tcp_hdr->fin == 1 && 
					 tcp_hdr->urg == 1 && 
					 tcp_hdr->psh == 1) 				{ type = XMAS; }

			else if (tcp_hdr->syn == 1 &&
					 tcp_hdr->ack == 0) 				{ type = SYN; }

			else if (tcp_hdr->fin == 1 &&
					 tcp_hdr->ack == 0) 				{ type = FIN; }
			
			else if (tcp_hdr->fin == 1 &&
					 tcp_hdr->ack == 1) 				{ type = FIN_ACK; }				

			else if (tcp_hdr->ack == 1 &&
					 tcp_hdr->syn == 0 &&
					 tcp_hdr->fin == 0 &&
					 tcp_hdr->rst == 0) 				{ type = ACK; }

			else if (tcp_hdr->fin == 0 &&
					tcp_hdr->syn == 0 &&
					tcp_hdr->rst == 0 && 
					tcp_hdr->psh == 0 &&
					tcp_hdr->ack == 0 &&
					tcp_hdr->urg == 0 &&
					tcp_hdr->ece == 0 &&
					tcp_hdr->cwr == 0)					{ type = NUL; }


			packet_t pkt = {  .type = type, 
							.four_tuple[0] = ip_header->saddr, 
							.four_tuple[1] = tcp_hdr->source, 
							.four_tuple[2] = ip_header->daddr,
							.four_tuple[3] = tcp_hdr->dest, 
							.timestamp = info->ts 
						};
			packet_t* p = &pkt;			

			receive_packet(p, flowtable, srctable);
		}
		print_portscanners(srctable);
		pcap_close(handle);
	}
	free_table(flowtable);
	free_table(srctable);
	return 0;
}
