/************************************************************************/
/* arp_spoof.h��������һЩ��ͷ�ṹ                                      */
/************************************************************************/
#ifndef __ARP_SPOOF
#define __ARP_SPOOF

#pragma pack (1)
#define  MAC_LEN	6

//��̫�������ʽ
typedef struct  __eth_header
{
	unsigned char	dst_mac[MAC_LEN]; //Ŀ��MAC��ַ 
	unsigned char	src_mac[MAC_LEN]; //ԴMAC��ַ 
	unsigned short	type;			//��̫������ 
} ETH_HEADER;

//ARPЭ������ʽ
typedef struct __arp_header {
	unsigned short	hardware_type;	//Ӳ�����ͣ���̫���ӿ�����Ϊ1 
	unsigned short	protocol_type;	//Э�����ͣ�IPЭ������Ϊ0X0800 
	unsigned char	hardware_len;	//Ӳ����ַ���ȣ�MAC��ַ����Ϊ6B 
	unsigned char	protocol_len;	//Э���ַ���ȣ�IP��ַ����Ϊ4B 
	unsigned short	option;			//ARP����Ϊ1��ARPӦ��Ϊ2 
	unsigned char	src_mac[MAC_LEN];	//ԴMAC
	unsigned long	src_ip;				//ԴIP 
	unsigned char	dst_mac[MAC_LEN];	//Ŀ��MAC
	unsigned long	dst_ip;				//Ŀ��IP
} ARP_HEADER;

//������ARP���ݰ���ʽ
typedef struct __arp_packet {
	ETH_HEADER eth_hdr;
	ARP_HEADER arp_hdr;
} ARP_PKT;

#endif