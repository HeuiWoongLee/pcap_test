#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <iostream>

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
        struct ether_header *eth_header;
        struct iphdr *ip_header;
        int res = pcap_next_ex(handle, &h, &p);

        eth_header = (struct ether_header*) p;
        ip_header = (struct iphdr*)(p+sizeof(struct ether_header));
        unsigned int ptype = ntohs(eth_header->ether_type);

        if(res == -1) break;
        if(res == 1){
            if(ptype == 2048){
                printf("Jacked a packet %p with length of [%d]%x\n", p, h->len, *p);
                printf("dst mac : [%02x:%02x:%02x:%02x:%02x:%02x] ",
                       eth_header->ether_dhost[0],
                        eth_header->ether_dhost[1],
                        eth_header->ether_dhost[2],
                        eth_header->ether_dhost[3],
                        eth_header->ether_dhost[4],
                        eth_header->ether_dhost[5]);
                printf("src mac : [%02x:%02x:%02x:%02x:%02x:%02x] ",
                       eth_header->ether_shost[0],
                        eth_header->ether_shost[1],
                        eth_header->ether_shost[2],
                        eth_header->ether_shost[3],
                        eth_header->ether_shost[4],
                        eth_header->ether_shost[5]);
                printf("protocol type : %04x\n", ptype);
                printf("src ip : %s\n", inet_ntoa(*(struct in_addr *)&ip_header->saddr));
                printf("dst ip : %s\n", inet_ntoa(*(struct in_addr *)&ip_header->daddr));

                switch(ip_header->protocol){
                    case 6: {printf("protocol : TCP\n"); break;};
                    case 17: {printf("protocol : UDP\n"); break;};
                    default: {printf("protocol : %d\n", ip_header->protocol); break;};
                }
            }

            else printf("no ip protocol\n");
        }
    }

    return(0);
}
