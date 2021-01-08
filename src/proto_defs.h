#define ETH_HEADER_LEN 14
#define ETH_ADDRESS_LEN 6


struct eth_hdr {
	unsigned char eth_source_addr[ETH_ADDRESS_LEN];
	unsigned char eth_dst_addr[ETH_HEADER_LEN];
	unsigned short eth_type;
};


struct ip_hdr {
	unsigned char ip_ver_and_hdr_len;
	unsigned char ip_tos;
	unsigned short ip_len;
	unsigned short ip_id;
	unsigned short ip_frag_offset;
	unsigned char ip_ttl;
	unsigned char ip_type;
	unsigned short ip_chksum;
	unsigned int ip_src_addr;
	unsigned int ip_dst_addr;
};

struct tcp_hdr {
	unsigned short tcp_src_port;
	unsigned short tcp_dst_port;

	unsigned int tcp_seq;
	unsigned int tcp_ack;

	unsigned char reserved:4;
	unsigned char tcp_offset:4;
	unsigned char tcp_flags;

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
	unsigned short tcp_window;
	unsigned short tcp_checksum;
	unsigned short tcp_urgent;
};

