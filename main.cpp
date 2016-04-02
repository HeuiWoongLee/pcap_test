#include <stdio.h>
#include <pcap.h>

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
        struct pcap_pkthdr *h;
        const u_char * p;
        int res = pcap_next_ex(handle, &h, &p);

        if(res == -1) break;
        if(res == 1) printf("Jacked a packet %p with length of [%d]%x\n", p, h->caplen, *p);
    }

    return(0);
}
