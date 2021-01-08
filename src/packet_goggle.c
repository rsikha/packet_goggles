#include <pcap.h>
#include "proto_defs.h"
#include "dump.h"


void capture_ip(const u_char *);
u_int capture_tcp(const u_char *);
void capture_eth(const u_char *);
void fatal(const char *);

void captured_packet(u_char *, const struct pcap_pkthdr *, const u_char *);


int main() {
	struct pcap_pkthdr cap_header;
	const u_char *pkt, *pkt_data;

	char err[PCAP_ERRBUF_SIZE];

	char *device;

	pcap_t *pcap_handle;
		
	//We know already the device name; let's skip it;
	printf("Starts sniffing\n");

	pcap_handle = pcap_open_live("wlp2s0", 4096, 1, 1000, err);

	if (pcap_handle == NULL) {
		fatal("No pcap_handle\n");
	}

	pcap_loop(pcap_handle, 30, captured_packet, NULL);

	pcap_close(pcap_handle);

}


void captured_packet(u_char *more_args, const struct pcap_pkthdr *cap_header, const u_char *pkt) {
	int tcp_hdr_len, total_hdr_size, pkt_data_len;
	u_char *pkt_data;

	printf("Got a packet of length: %d\n", cap_header->len);
	capture_eth(pkt);
	capture_ip(pkt+ETH_HEADER_LEN);
	tcp_hdr_len=capture_tcp(pkt+ETH_HEADER_LEN+sizeof(struct ip_hdr));
	printf("TCP HDR LEN: %d\n",tcp_hdr_len);
	total_hdr_size = ETH_HEADER_LEN+sizeof(struct ip_hdr)+tcp_hdr_len;
	pkt_data = (u_char *) pkt + total_hdr_size;
	pkt_data_len = cap_header->len - total_hdr_size;

	if (pkt_data_len > 0) {
		printf("\n\n%u bytes of packet data\n", pkt_data_len);
		dump(pkt_data, pkt_data_len);
	} 
	else {
		printf("No packet data\n");
	}
}

void capture_eth(const u_char *hdr_start) {
	int i;
	const struct eth_hdr *e_hdr;

	e_hdr = (const struct eth_hdr *) hdr_start;
	printf("[SRC MAC ADDR => ");
	for (i=0; i < ETH_ADDRESS_LEN; i++) {
		printf("%02x", e_hdr->eth_source_addr[i]);
		if (i != ETH_ADDRESS_LEN -1)
			printf(":");
		else
			printf("]");
	}
	printf("\t[DST MAC ADDR => ");
	for (i=0; i < ETH_ADDRESS_LEN; i++) {
		printf("%02x", e_hdr->eth_dst_addr[i]);
		if (i != ETH_ADDRESS_LEN -1)
			printf(":");
		else
			printf("]");
	}

}

void capture_ip(const u_char *hdr_start) {
	const struct ip_hdr *ip_hdr;

	ip_hdr = (const struct ip_hdr *)hdr_start;
	printf("\n[IP SRC: %s] ", inet_ntoa(*(struct in_addr *)&ip_hdr->ip_src_addr)); 
	printf("\t\t[IP DST: %s]\n", inet_ntoa(*(struct in_addr *)&ip_hdr->ip_dst_addr)); 
}

u_int capture_tcp(const u_char *hdr_start) {
	u_int hdr_size;
	const struct tcp_hdr *tcp_header;

	tcp_header = (const struct tcp_hdr *) hdr_start;
	hdr_size = 4 * tcp_header->tcp_offset;

	printf("TCP\n");
	printf("\tSRC PORT: %d\n", ntohs(tcp_header->tcp_src_port));
	printf("\tDST PORT: %d\n", ntohs(tcp_header->tcp_dst_port));
	printf("\tSeq: %u\n", ntohs(tcp_header->tcp_seq));
	printf("\tAck: %u\n", ntohs(tcp_header->tcp_ack));
	printf("\tHeader size: %u\n", hdr_size);

	if(tcp_header->tcp_flags & TCP_FIN)
		printf("\t\tFIN\n");

	if(tcp_header->tcp_flags & TCP_SYN)
		printf("\t\tSYN\n");
	if(tcp_header->tcp_flags & TCP_RST)
		printf("\t\tRST\n");
	if(tcp_header->tcp_flags & TCP_PUSH)
		printf("\t\tpush\n");
	if(tcp_header->tcp_flags & TCP_ACK)
		printf("\t\tACK\n");
	if(tcp_header->tcp_flags & TCP_URG)
		printf("\t\tURG\n");

	return hdr_size;
}
