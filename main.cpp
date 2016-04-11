#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
/*#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>*/
#include <libnet.h>

void *ethernet_handler(void *arg)
{
    struct libnet_ethernet_hdr* eth_h = (struct libnet_ethernet_hdr*) arg;

    printf("dst mac : [%02x:%02x:%02x:%02x:%02x:%02x] src mac : [%02x:%02x:%02x:%02x:%02x:%02x] ",
           eth_h->ether_dhost[0],
            eth_h->ether_dhost[1],
            eth_h->ether_dhost[2],
            eth_h->ether_dhost[3],
            eth_h->ether_dhost[4],
            eth_h->ether_dhost[5],
            eth_h->ether_shost[0],
            eth_h->ether_shost[1],
            eth_h->ether_shost[2],
            eth_h->ether_shost[3],
            eth_h->ether_shost[4],
            eth_h->ether_shost[5]);

    return 0;
}

int main(/*int argc, char *argv[]*/)
{
    char *dev, errbuf[PCAP_ERRBUF_SIZE];

    dev = pcap_lookupdev(errbuf);

    if (dev == NULL){
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);

        return(2);
    }

    printf("Device: %s\n", dev);

    pcap_t *handle;
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL){
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);

        return(2);
    }

    while(1){
        const u_char *p;
        struct pcap_pkthdr *h;
        struct libnet_ethernet_hdr *eth_header;
        int res = pcap_next_ex(handle, &h, &p);
        unsigned int ptype = ntohs(eth_header->ether_type);

        eth_header = (struct libnet_ethernet_hdr*)p;

        if(res == -1) break;
        if(res == 1){
            if(ptype == ETHERTYPE_IP){
//                printf("Jacked a packet %p with length of [%d]%x\n", p, h->len, *p);
                struct libnet_ipv4_hdr *ip_header = (struct libnet_ipv4_hdr*)(p + sizeof(struct libnet_ethernet_hdr));
                ethernet_handler((void *)p);
                printf("protocol type : %04x\n", ptype);
                printf("src ip : %s\n", inet_ntoa(*(struct in_addr *)&ip_header->ip_src));
                printf("dst ip : %s\n", inet_ntoa(*(struct in_addr *)&ip_header->ip_dst));

                switch(ip_header->ip_p){
                case IPPROTO_TCP: {
                    struct libnet_tcp_hdr *tcp_header = (struct libnet_tcp_hdr*)(ip_header + 1);
                    printf("protocol : TCP\n");
                    printf("src port : %d ", ntohs(tcp_header->th_sport));
                    printf("dst port : %d\n", ntohs(tcp_header->th_dport));

                    break;};

                case IPPROTO_UDP: {
                    struct libnet_udp_hdr *udp_header = (struct libnet_udp_hdr*)(ip_header + 1);
                    printf("protocol : UDP\n");
                    printf("src port : %d ", ntohs(udp_header->uh_sport));
                    printf("dst port : %d\n", ntohs(udp_header->uh_dport));

                    break;};

                default: {
                    printf("protocol : %d\n", ip_header->ip_p);

                    break;};
                }
            }

            else printf("no ip protocol\n");
        }
    }

    return(0);
}
