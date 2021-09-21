/************************************************************************/
/* arp_spoof.h——定义一些报头结构                                      */
/************************************************************************/
#ifndef __ARP_SPOOF
#define __ARP_SPOOF

#pragma pack (1)
#define  MAC_LEN	6

//以太网分组格式
typedef struct  __eth_header
{
	unsigned char	dst_mac[MAC_LEN]; //目标MAC地址 
	unsigned char	src_mac[MAC_LEN]; //源MAC地址 
	unsigned short	type;			//以太网类型 
} ETH_HEADER;

//ARP协议分组格式
typedef struct __arp_header {
	unsigned short	hardware_type;	//硬件类型：以太网接口类型为1 
	unsigned short	protocol_type;	//协议类型：IP协议类型为0X0800 
	unsigned char	hardware_len;	//硬件地址长度：MAC地址长度为6B 
	unsigned char	protocol_len;	//协议地址长度：IP地址长度为4B 
	unsigned short	option;			//ARP请求为1，ARP应答为2 
	unsigned char	src_mac[MAC_LEN];	//源MAC
	unsigned long	src_ip;				//源IP 
	unsigned char	dst_mac[MAC_LEN];	//目的MAC
	unsigned long	dst_ip;				//目的IP
} ARP_HEADER;

//完整的ARP数据包格式
typedef struct __arp_packet {
	ETH_HEADER eth_hdr;
	ARP_HEADER arp_hdr;
} ARP_PKT;

#endif