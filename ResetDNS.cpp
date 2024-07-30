#include <stdio.h>
#include <pcap.h>
#include <time.h>

#pragma comment(lib, "wpcap")
#pragma comment(lib, "ws2_32")

#include <tchar.h>
#include <WinSock2.h>

#define DNS_PORT 53
#define REDIRECT_IP "93.184.216.34"  // example.com IP
#define IPADDR_LEN 4
#define PACKET_LENGTH 1514          // 1500(IP header(20) + TCP header(20) + real data payload(1460)) + 18(Ethernet header) = Ethernet MTU


#pragma pack(push, 1)
typedef struct EtherHeader {
	unsigned char dstMac[6];
	unsigned char srcMac[6];
	unsigned short type;
} EtherHeader;

typedef struct IpHeader {
	unsigned char verIhl;
	unsigned char tos;
	unsigned short length;
	unsigned short id;
	unsigned short fragOffset;
	unsigned char ttl;
	unsigned char protocol;
	unsigned short checksum;
	unsigned char srcIp[4];
	unsigned char dstIp[4];
} IpHeader;

typedef struct TcpHeader {
	unsigned short srcPort;
	unsigned short dstPort;
	unsigned int seq;
	unsigned int ack;
	unsigned char data;
	unsigned char flags;
	unsigned short windowSize;
	unsigned short checksum;
	unsigned short urgent;
} TcpHeader;


typedef struct {
	u_short id;
	u_short flags;
	u_short qdcount;
	u_short ancount;
	u_short nscount;
	u_short arcount;
} DnsHeader;

typedef struct PseudoHeader {
	unsigned int srcIp;
	unsigned int dstIp;
	unsigned char zero;
	unsigned char protocol;
	unsigned short length;
} PseudoHeader;

typedef struct {
	pcap_t* handle;
} UserData;

typedef struct dns_response {
	u_short         offset;                     /*offset for the DNS response part*/
	u_long          ttl;                        /*time to live*/
	u_short         len;                        /*data length*/
	u_short         type;                       /*domain type*/
	u_short         cls;                      /*domain class*/
	u_char          ip_addr[IPADDR_LEN];
} DnsResponse;
#pragma pack(pop)

BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}

	return TRUE;
}

unsigned short CalcChecksumIp(IpHeader* pIpHeader)
{
	unsigned char ihl = (pIpHeader->verIhl & 0x0F) << 2; //*4와 동일
	unsigned short wData[30] = { 0 };
	unsigned int dwSum = 0;

	memcpy(wData, (BYTE*)pIpHeader, ihl);

	for (int i = 0; i < ihl / 2; i++)
	{
		if (i != 5)
			dwSum += wData[i];

		if (dwSum & 0xFFFF0000)
		{
			dwSum &= 0x0000FFFF;
			dwSum++;
		}
	}

	return ~(dwSum & 0x0000FFFF);
}

unsigned short CalcChecksumTcp(IpHeader* pIpHeader, TcpHeader* pTcpHeader)
{
	PseudoHeader	pseudoHeader = { 0 };
	unsigned short* pwPseudoHeader = (unsigned short*)&pseudoHeader;
	unsigned short* pwDatagram = (unsigned short*)pTcpHeader;
	int				nPseudoHeaderSize = 6; //WORD 6개 배열
	int				nSegmentSize = 0; //헤더 포함

	UINT32			dwSum = 0;
	int				nLengthOfArray = 0;

	pseudoHeader.srcIp = *(unsigned int*)pIpHeader->srcIp;
	pseudoHeader.dstIp = *(unsigned int*)pIpHeader->dstIp;
	pseudoHeader.zero = 0;
	pseudoHeader.protocol = 6;
	pseudoHeader.length = htons(ntohs(pIpHeader->length) - 20);


	nSegmentSize = ntohs(pseudoHeader.length);

	if (nSegmentSize % 2)
		nLengthOfArray = nSegmentSize / 2 + 1;
	else
		nLengthOfArray = nSegmentSize / 2;

	for (int i = 0; i < nPseudoHeaderSize; i++)
	{
		dwSum += pwPseudoHeader[i];
		if (dwSum & 0xFFFF0000)
		{
			dwSum &= 0x0000FFFF;
			dwSum++;
		}
	}

	for (int i = 0; i < nLengthOfArray; i++)
	{
		if (i != 8)
			dwSum += pwDatagram[i];
		if (dwSum & 0xFFFF0000)
		{
			dwSum &= 0x0000FFFF;
			dwSum++;
		}
	}

	return (USHORT)~(dwSum & 0x0000FFFF);
}


char* decode_dns_name(const u_char* data, int* offset) {
	char name[256] = { 0 };  // 초기화
	int pos = *offset;
	int length = 0;
	while (data[pos] != 0) {
		if ((data[pos] & 0xC0) == 0xC0) {
			int pointer = ((data[pos] & 0x3F) << 8) | data[pos + 1];
			pos = pointer;
		}
		else {
			int label_len = data[pos];
			pos++;
			if (length + label_len + 1 >= sizeof(name)) break;  // +1 for '.'
			memcpy(name + length, data + pos, label_len);
			length += label_len;
			pos += label_len;
			name[length++] = '.';
		}
	}
	char* decoded_name = (char*)malloc(length + 1);
	if (decoded_name == NULL) {
		return NULL;
	}
	memcpy(decoded_name, name, length);
	if (length > 0) {
		decoded_name[length - 1] = '\0';  // 마지막 '.' 제거
	}
	else {
		decoded_name[0] = '\0';  // 빈 문자열 처리
	}
	*offset = pos + 1;  // null byte 이후로 오프셋 이동

	return decoded_name;
}

unsigned int calculate_next_seq(IpHeader* ipHeader, TcpHeader* tcpHeader) {
	// Convert network byte order to host byte order
	unsigned short ipTotalLength = ntohs(ipHeader->length);

	// Calculate IP header length
	unsigned int ipHeaderLength = (ipHeader->verIhl & 0x0F) * 4;

	// Calculate TCP header length
	unsigned int tcpHeaderLength = (tcpHeader->data >> 4) * 4;

	// Calculate TCP segment payload length
	unsigned int payloadLength = ipTotalLength - ipHeaderLength - tcpHeaderLength;

	// Calculate the next sequence number
	unsigned int nextSeq = ntohl(tcpHeader->seq) + payloadLength;

	return nextSeq;
}

void dns_redirect(UserData* userData, u_char* packet, int len) {
	EtherHeader* eth = (EtherHeader*)packet;
	IpHeader* ip = (IpHeader*)(packet + sizeof(EtherHeader));
	TcpHeader* tcp = (TcpHeader*)(packet + sizeof(EtherHeader) + (ip->verIhl & 0x0F) * 4);

	int tcpHeaderLen = (tcp->data >> 4) * 4;
	DnsHeader* dns = (DnsHeader*)(packet + sizeof(EtherHeader) + (ip->verIhl & 0x0F) * 4 + tcpHeaderLen);

	// Parse DNS query
	int pos = sizeof(DnsHeader);
	char* domain = decode_dns_name((u_char*)dns, &pos);
	//fprintf(stdout, "curr Domain: %s \n", domain);

	if (strcmp(domain, "www.*****.com") == 0) {
		//fprintf(stdout, "Disconnecting %s \n", domain);

		// Create buffer for the new packet
		u_char buf[PACKET_LENGTH];
		memset(buf, 0, PACKET_LENGTH);
		memcpy(buf, packet, len);

		// Update Ethernet header
		EtherHeader* eth_send = (EtherHeader*)buf;
		memcpy(eth_send->srcMac, eth->dstMac, 6);
		memcpy(eth_send->dstMac, eth->srcMac, 6);

		// Update IP header
		IpHeader* ip_send = (IpHeader*)(buf + sizeof(EtherHeader));
		memcpy(ip_send->srcIp, ip->dstIp, 4);
		memcpy(ip_send->dstIp, ip->srcIp, 4);
		ip_send->verIhl = 0x45; // ipv4, 20바이트 헤더
		ip_send->tos = 0x00;
		ip_send->length = htons(40);
		ip_send->id = 0x3412;
		ip_send->fragOffset = htons(0x4000); //DF
		ip_send->ttl = 0xFF;
		ip_send->protocol = 6; // TCP
		ip_send->length = htons(40);

		// Update TCP header
		TcpHeader* tcp_send = (TcpHeader*)(buf + sizeof(EtherHeader) + (ip_send->verIhl & 0x0F) * 4);
		tcp_send->srcPort = tcp->dstPort;
		tcp_send->dstPort = tcp->srcPort;
		tcp_send->ack = 0;
		tcp_send->data = (sizeof(TcpHeader) / 4) << 4;
		tcp_send->seq = tcp->ack; // RST 패킷은 ACK 번호를 기반으로 함
		tcp_send->flags = 0x04; // RST
		tcp_send->windowSize = 0;
		tcp_send->urgent = 0;

		ip_send->checksum = 0;
		ip_send->checksum = CalcChecksumIp(ip_send);
		tcp_send->checksum = 0;
		tcp_send->checksum = CalcChecksumTcp(ip_send, tcp_send);

		// Update lengths and checksums
		int newLen = sizeof(EtherHeader) + ntohs(ip_send->length);

		// Send the packet
		pcap_t* handle = userData->handle;
		if (pcap_sendpacket(handle, buf, newLen) != 0) {
			fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
		}
	}

	free(domain);
}

void dispatcher_handler(u_char* user,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data)
{
	EtherHeader* pEther = (EtherHeader*)pkt_data;
	IpHeader* pIpHeader = (IpHeader*)(pkt_data + sizeof(EtherHeader));

	if (pEther->type != 0x0008)
		return;

	if (pIpHeader->protocol != 6)
		return;

	int ipLen = (pIpHeader->verIhl & 0x0F) * 4;
	TcpHeader* pTcp =
		(TcpHeader*)(pkt_data + sizeof(EtherHeader) + ipLen);

	UserData* userData = (UserData*)user;

	if (ntohs(pTcp->dstPort) == DNS_PORT
		//|| ntohs(pTcp->srcPort) == DNS_PORT
		) {
		dns_redirect(userData, (u_char*)pkt_data, header->len);
	}

}


int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "tcp port 53";
	struct pcap_pkthdr* header;
	const u_char* pkt_data;

	if (!LoadNpcapDlls())
	{
		fprintf(stderr, "Couldn't load Npcap\n");
		exit(1);
	}


	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
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
		printf("\nNo interfaces found! Make sure Npcap is installed.\n");
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
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the device */
	/* Open the adapter */
	/*
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		8192,			// portion of the packet to capture.
		1,				// promiscuous mode (nonzero means promiscuous)
		1,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
		pcap_freealldevs(alldevs); // free the device list
		return -1;
	}
	*/

	// Create the pcap handle
	adhandle = pcap_create(d->name, errbuf);
	if (adhandle == NULL) {
		fprintf(stderr, "Unable to create the adapter. %s is not supported by Npcap\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	// Set immediate mode
	if (pcap_set_immediate_mode(adhandle, 1) != 0) {
		fprintf(stderr, "Error setting immediate mode: %s\n", pcap_geterr(adhandle));
		pcap_close(adhandle);
		return 2;
	}

	// Set timeout
	if (pcap_set_timeout(adhandle, 10) != 0) {
		fprintf(stderr, "Error setting timeout: %s\n", pcap_geterr(adhandle));
		pcap_close(adhandle);
		return 2;
	}

	// Activate the pcap handle
	if (pcap_activate(adhandle) != 0) {
		fprintf(stderr, "Error activating the pcap handle: %s\n", pcap_geterr(adhandle));
		pcap_close(adhandle);
		return 2;
	}

	if (pcap_compile(adhandle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(adhandle));
		return 2;
	}

	if (pcap_setfilter(adhandle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(adhandle));
		return 2;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	UserData userData;
	userData.handle = adhandle;

	/* start the capture */
	//pcap_loop(adhandle, 0, dispatcher_handler, (u_char*)&userData);

	int res;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
	{
		if (res == 0)
		{
			// 타임아웃 발생
			continue;
		}
		// 패킷 처리 함수 호출
		dispatcher_handler((u_char*)&userData, header, pkt_data);
	}

	pcap_close(adhandle);

	return 0;
}
