#include <stdio.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <linux/if_ether.h>

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
        struct ether_header *header;
        int res = pcap_next_ex(handle, &h, &p);

        header = (struct ether_header*) p;
        unsigned int ptype = ntohs(header->ether_type);

        if(res == -1) break;
        if(res == 1){
            printf("Jacked a packet %p with length of [%d]%x\n", p, h->caplen, *p);
            printf("dst mac : [%02x:%02x:%02x:%02x:%02x:%02x] ",
                   header->ether_dhost[0],
                    header->ether_dhost[1],
                    header->ether_dhost[2],
                    header->ether_dhost[3],
                    header->ether_dhost[4],
                    header->ether_dhost[5]);
            printf("src mac : [%02x:%02x:%02x:%02x:%02x:%02x] ",
                   header->ether_shost[0],
                    header->ether_shost[1],
                    header->ether_shost[2],
                    header->ether_shost[3],
                    header->ether_shost[4],
                    header->ether_shost[5]);
            printf("protocol type : %04x\n", ptype);
        }
    }

    return(0);
}
