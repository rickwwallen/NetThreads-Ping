#include "common.h"
#include "pktbuff.h"
#include "dev.h"
#include "support.h"

#define ARP_PKT_SIZE (sizeof(struct ioq_header)  + sizeof(struct ether_header) + sizeof(struct ether_arp))
#define ICMP_PKT_SIZE (sizeof(struct ioq_header)  + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 512)

u_int16_t ones_complement_sum(char *data, int len) {
	u_int32_t sum = 0;
	while (len > 1)
	{
		/*  This is the inner loop */
		sum += * (unsigned short*) data;
		data += 2;
		//data++;
		len -= 2;
	}

	/*  Add left-over byte, if any */
	if( len > 0 )
		sum += * (unsigned char *) data;
  
	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
  
	//return (u_int16_t) sum;
	return (u_int16_t) ~sum;
}

//int process_icmp(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, struct icmphdr *icmp, t_addr *pkt)
//int process_icmp(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, t_addr *pkt)
int process_icmp(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, struct pkt_buff *pkt)
{
	struct icmphdr *icmp;
	t_addr *reply;
	struct ether_header *reth;
	struct iphdr *rip;
	struct icmphdr *ricmp;
	u_int32_t acc;

	// Declare ICMP header here
	icmp = pkt_pull(pkt, sizeof(struct icmphdr));

	// allocate reply size
	reply = nf_pktout_alloc(ICMP_PKT_SIZE);

	// setup the ioq_header
	fill_ioq((struct ioq_header*) reply, 2, ICMP_PKT_SIZE);
	
	// setup the ethernet header
	reth = (struct ether_header*) (reply + sizeof(struct ioq_header));

	// setup the ip header
	rip = (struct iphdr*) (reply + sizeof(struct ioq_header) + sizeof(struct ether_header));

	// setup the icmp header	
	ricmp = (struct icmp*) (reply + sizeof(struct ioq_header) + sizeof(struct ether_header) + sizeof(struct iphdr));

	// start putting things into the packet
	// ethernet
	memcpy(reth->ether_shost, iface->mac, ETH_ALEN);
	memcpy(reth->ether_dhost, eth->ether_shost, ETH_ALEN);
	reth->ether_type = ETHERTYPE_IP;

	// ip
	rip->version_ihl = 0x45;
	rip->tos = ip->tos; // not sure about this one
	rip->tot_len = ip->tot_len;
	rip->id = ip->id + 12; // not sure about this one
	//rip->id = 1988; // not sure about this one
	rip->frag_off = ip->frag_off;
	rip->ttl = ip->ttl--;
	rip->protocol = IPPROTO_ICMP;
	rip->saddr_h = ip->daddr_h;
	rip->saddr_l = ip->daddr_l;
	rip->daddr_h = ip->saddr_h;
	rip->daddr_l = ip->saddr_l;
	//rip->check = ones_complement_sum(rip, ntohs(ip->tot_len));
	rip->check = ntohs(0);
	acc = ones_complement_sum(rip, htons(ip->tot_len));
	rip->check = htons(acc);
	acc = 0;
	// fill icmp
	memcpy(ricmp, icmp, (ntohs(ip->tot_len) - sizeof(struct iphdr)));

	ricmp->type = ICMP_ECHOREPLY;

	// init checksum to zero to calcualate
	ricmp->checksum = ntohs(0);

	// calculate checksum
	acc = ones_complement_sum(ricmp, (ntohs(ip->tot_len) - sizeof(struct iphdr)));

	// assign checksum
	ricmp->checksum = htons(acc);

	// send it
	nf_pktout_send(reply, reply + (htons(ioq->byte_length)) + sizeof(struct ioq_header)); 

	return 0;
}

//int process_ip(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct iphdr *ip, struct icmphdr *icmp, t_addr *pkt)
//int process_ip(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, t_addr *pkt)
int process_ip(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct pkt_buff *pkt)
{
	int result;
	struct iphdr *my_ip;

	// New ip header pointer
	my_ip = pkt_pull(pkt, sizeof(struct iphdr));
	//my_ip = (struct iphdr*) &eth + sizeof(struct ether_header);

	//switch (ip->protocol)
	switch (my_ip->protocol)
	{
		case IPPROTO_ICMP:
			//result = process_icmp(iface, ioq, eth, ip, icmp, pkt);
			result = process_icmp(iface, ioq, eth, my_ip, pkt);
			break;
		default:
			result = 1;
			break;
	}
	return result;
}

//int process_arp(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct ether_arp *etharp, t_addr *pkt)
//int process_arp(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, t_addr *pkt)
int process_arp(struct net_iface *iface, struct ioq_header *ioq, struct ether_header *eth, struct pkt_buff *pkt)
{
	unsigned short int my_hrd;
	unsigned short int my_pro;
	struct ether_arp *my_etharp;
	t_addr *reply;
	struct ether_header *reth;
	struct ether_arp *rarp;


	my_hrd = 6;		// set to mac(6)
	my_pro = 4;		// set to ipv4(4)

	// Testing how to make new pointer point to the correct location
	my_etharp = pkt_pull(pkt, sizeof(struct ether_arp));

	// If we aren't getting a request or reply we don't care
	//if(ntohs(etharp->ea_hdr.ar_hrd) != ARPHRD_ETHER || 
	//	ntohs(etharp->ea_hdr.ar_pro) !=  ETHERTYPE_IP ||
	//	etharp->ea_hdr.ar_hln != my_hrd ||
	//	etharp->ea_hdr.ar_pln != my_pro ||
	//	(
	//		ntohs(etharp->ea_hdr.ar_op) != ARPOP_REPLY &&
	//		ntohs(etharp->ea_hdr.ar_op) != ARPOP_REQUEST
	//	)
	//)
	//{
	//	return 1;
	//}
	//if(memcmp(htonl(etharp->arp_tpa), iface->ip, 4) == 0)
	//{
	//	if(ntohs(etharp->ea_hdr.ar_op) == ARPOP_REQUEST)
	//	{
	//		// allocate reply size
	//		reply = nf_pktout_alloc(ARP_PKT_SIZE);

	//		// setup the ioq_header
	//		fill_ioq((struct ioq_header*) reply, 2, ARP_PKT_SIZE);

	//		// setup the ethernet header
	//		reth = (struct ether_header*) (reply + sizeof(struct ioq_header));

	//		// setup the ethernet arp
	//		rarp = (struct ether_arp*) (reply + sizeof(struct ioq_header) + sizeof(struct ether_header));
	//	
	//		// start putting things into the packet
	//		// ethernet
	//		memcpy(reth->ether_shost, iface->mac, ETH_ALEN);
	//		memcpy(reth->ether_dhost, eth->ether_shost, ETH_ALEN);
	//		reth->ether_type = ETHERTYPE_ARP;

	//		// arp header
	//		rarp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
	//		rarp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
	//		rarp->ea_hdr.ar_hln = 6;
	//		rarp->ea_hdr.ar_pln = 4;
	//		rarp->ea_hdr.ar_op = htons(ARPOP_REPLY);

	//		// arp ethernet
	//			// source
	//		memcpy(rarp->arp_sha, iface->mac, ETH_ALEN);
	//		memcpy(rarp->arp_spa, iface->ip, 4);
	//			// target
	//		memcpy(rarp->arp_tha, etharp->arp_sha, ETH_ALEN);
	//		memcpy(rarp->arp_tpa, etharp->arp_spa, 4);

	//		// send it
	//		nf_pktout_send(reply, reply + ARP_PKT_SIZE); 
	//	}
	//}
	// Test my_etharp
	// If we aren't getting a request or reply we don't care
	if(ntohs(my_etharp->ea_hdr.ar_hrd) != ARPHRD_ETHER || 
		ntohs(my_etharp->ea_hdr.ar_pro) !=  ETHERTYPE_IP ||
		my_etharp->ea_hdr.ar_hln != my_hrd ||
		my_etharp->ea_hdr.ar_pln != my_pro ||
		(
			ntohs(my_etharp->ea_hdr.ar_op) != ARPOP_REPLY &&
			ntohs(my_etharp->ea_hdr.ar_op) != ARPOP_REQUEST
		)
	)
	{
		return 1;
	}
	if(memcmp(htonl(my_etharp->arp_tpa), iface->ip, 4) == 0)
	{
		if(ntohs(my_etharp->ea_hdr.ar_op) == ARPOP_REQUEST)
		{
			// allocate reply size
			reply = nf_pktout_alloc(ARP_PKT_SIZE);

			// setup the ioq_header
			fill_ioq((struct ioq_header*) reply, 2, ARP_PKT_SIZE);

			// setup the ethernet header
			reth = (struct ether_header*) (reply + sizeof(struct ioq_header));

			// setup the ethernet arp
			rarp = (struct ether_arp*) (reply + sizeof(struct ioq_header) + sizeof(struct ether_header));
		
			// start putting things into the packet
			// ethernet
			memcpy(reth->ether_shost, iface->mac, ETH_ALEN);
			memcpy(reth->ether_dhost, eth->ether_shost, ETH_ALEN);
			reth->ether_type = ETHERTYPE_ARP;

			// arp header
			rarp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
			rarp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
			rarp->ea_hdr.ar_hln = 6;
			rarp->ea_hdr.ar_pln = 4;
			rarp->ea_hdr.ar_op = htons(ARPOP_REPLY);

			// arp ethernet
				// source
			memcpy(rarp->arp_sha, iface->mac, ETH_ALEN);
			memcpy(rarp->arp_spa, iface->ip, 4);
				// target
			memcpy(rarp->arp_tha, my_etharp->arp_sha, ETH_ALEN);
			memcpy(rarp->arp_tpa, my_etharp->arp_spa, 4);

			// send it
			nf_pktout_send(reply, reply + ARP_PKT_SIZE); 
		}
	}
	return 0;
} 

int process_eth(struct net_iface *iface, t_addr *data)
{
	//t_addr *my_pkt;
	struct pkt_buff my_pkt; 
	int result;
	struct ioq_header *ioq;
	struct ether_header *eth;
	//unsigned int size;
	//struct ether_arp *etharp;
	//struct iphdr *ip;
	//struct icmphdr *icmp;

	result = 0;

	ioq = data;

	pkt_fill(&my_pkt, data,  ntohs(ioq->byte_length) + sizeof(struct ioq_header));
	pkt_pull(&my_pkt, sizeof(struct ioq_header));
	eth = pkt_pull(&my_pkt, sizeof(struct ether_header));

	//my_pkt = nf_pktout_alloc(ntohs(ioq->byte_length) + sizeof(struct ioq_header));
	//memcpy(my_pkt, data, ntohs(ioq->byte_length) + sizeof(struct ioq_header));

	//ioq = my_pkt;
	//size = ntohs(ioq->byte_length);
	//eth = (struct ether_header*) (my_pkt + sizeof(struct ioq_header));

	//ioq = data;
	//size = ntohs(ioq->byte_length);

	//eth = (struct ether_header*) (data + sizeof(struct ioq_header));
	switch (ntohs(eth->ether_type))
	{
		case ETHERTYPE_ARP:
			//etharp = (struct ether_arp*) (data + 
			//		sizeof(struct ioq_header) + 
			//		sizeof(struct ether_header));
			//result = process_arp(iface, ioq, eth, etharp, data);
			//result = process_arp(iface, ioq, eth, pkt);
			//result = process_arp(iface, ioq, eth, data);
			result = process_arp(iface, ioq, eth, &my_pkt);
			break;
		case ETHERTYPE_IP:
			//ip = (struct iphdr*) (data + 
			//		sizeof(struct ioq_header) + 
			//		sizeof(struct ether_header));
			//icmp = (struct icmphdr*) (data +
			//		sizeof(struct ioq_header) +
			//		sizeof(struct ether_header)+
			//		sizeof(struct iphdr));
			//udp = (struct icmphdr*) (data +
			//		sizeof(struct ioq_header) +
			//		sizeof(struct ether_header)+
			//		sizeof(struct iphdr));
			//result = process_ip(iface, ioq, eth, ip, icmp, data);
			//result = process_ip(iface, ioq, eth, data);
			result = process_ip(iface, ioq, eth, &my_pkt);
		default:
			//result = process_arp(iface, ioq, eth, my_pkt);
			result = 1;
			break;
	}
	return result;
}

int main(void)
{
	t_addr *pkt;
	struct net_iface iface;
	struct ether_header *reth;
	struct ether_arp *rarp;
	unsigned char dest_mac[6];
	unsigned char dest_ip[4];
	
	// iface is not shared, it's on the stack
	arp_init(&iface.arp);

	iface.mac[0] = 0x00;
	iface.mac[1] = 0x43;
	iface.mac[2] = 0x32;
	iface.mac[3] = 0x46;
	iface.mac[4] = 0x4e;
	iface.mac[5] = 0x00;

	iface.ip[0] = 192;
	iface.ip[1] = 168;
	iface.ip[2] = 0;
	iface.ip[3] = 100;

	dest_mac[0] = 0xff;
	dest_mac[1] = 0xff;
	dest_mac[2] = 0xff;
	dest_mac[3] = 0xff;
	dest_mac[4] = 0xff;
	dest_mac[5] = 0xff;

	dest_ip[0] = 192;
	dest_ip[1] = 168;
	dest_ip[2] = 0;
	dest_ip[3] = 1;
	//dest_ip[3] = 185;

	//only run this program on thread 0
	if (nf_tid() != 0) 
	{
	   while (1) {}
	}
	
	// initialize
	nf_pktout_init();
	nf_pktin_init();

	// This sends an initial request to the route
	// Purpose is to let everyone know we have joined the network
	// This is to just send an ARP request to router
	// allocate an output buffer
	pkt = nf_pktout_alloc(ARP_PKT_SIZE);

	// setup the ioq_header
	fill_ioq((struct ioq_header*) pkt, 2, ARP_PKT_SIZE);

	// setup the ethernet header
	reth = (struct ether_header*) (pkt + sizeof(struct ioq_header));
 
	// setup the ethernet arp
	rarp = (struct ether_arp*) (pkt + sizeof(struct ioq_header) + sizeof(struct ether_header));

	// start putting things into the packet
	// ethernet
	memcpy(reth->ether_shost, &iface.mac, ETH_ALEN);
	memcpy(reth->ether_dhost, &dest_mac, ETH_ALEN);
	reth->ether_type = ETHERTYPE_ARP;

	// arp header
	rarp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
	rarp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
	rarp->ea_hdr.ar_hln = 6;
	rarp->ea_hdr.ar_pln = 4;
	rarp->ea_hdr.ar_op = htons(ARPOP_REQUEST);

	// arp ethernet
		// source
	memcpy(rarp->arp_sha, &iface.mac, ETH_ALEN);
	memcpy(rarp->arp_spa, &iface.ip, 4);
		// target
	memcpy(rarp->arp_tha, dest_mac, ETH_ALEN);
	memcpy(rarp->arp_tpa, dest_ip, 4);

	// send it
	nf_pktout_send(pkt, pkt + ARP_PKT_SIZE); 

//	dest_ip[0] = 192;
//	dest_ip[1] = 168;
//	dest_ip[2] = 0;
//	dest_ip[3] = 2;
//
//	// This is to just send an ARP request to switch
//	// allocate an output buffer
//	//pkt = nf_pktout_alloc(ARP_PKT_SIZE);
//
//	// setup the ioq_header
//	//fill_ioq((struct ioq_header*) pkt, 2, ARP_PKT_SIZE);
//
//	// setup the ethernet header
//	reth = (struct ether_header*) (pkt + sizeof(struct ioq_header));
// 
//	// setup the ethernet arp
//	rarp = (struct ether_arp*) (pkt + sizeof(struct ioq_header) + sizeof(struct ether_header));
//
//	// start putting things into the packet
//	// ethernet
//	memcpy(reth->ether_shost, &iface.mac, ETH_ALEN);
//	memcpy(reth->ether_dhost, &dest_mac, ETH_ALEN);
//	reth->ether_type = ETHERTYPE_ARP;
//
//	// arp header
//	rarp->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
//	rarp->ea_hdr.ar_pro = htons(ETHERTYPE_IP);
//	rarp->ea_hdr.ar_hln = 6;
//	rarp->ea_hdr.ar_pln = 4;
//	rarp->ea_hdr.ar_op = htons(ARPOP_REQUEST);
//
//	// arp ethernet
//		// source
//	memcpy(rarp->arp_sha, &iface.mac, ETH_ALEN);
//	memcpy(rarp->arp_spa, &iface.ip, 4);
//		// target
//	memcpy(rarp->arp_tha, dest_mac, ETH_ALEN);
//	memcpy(rarp->arp_tpa, dest_ip, 4);
//
//	// send it
//	nf_pktout_send(pkt, pkt + ARP_PKT_SIZE); 
//
//	nf_pktin_free(pkt);
	
	// start in on replying
	while(1)
	{
		pkt = nf_pktin_pop();  // test for next_packet
		if(!nf_pktin_is_valid(pkt))
			continue;

		process_eth(&iface, pkt);

		nf_pktin_free(pkt);
	} 

	// never reached
	return 0;
}
