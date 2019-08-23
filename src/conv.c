/*
 * Proof-of-concept Cisco GRE decapsulator - Corey Satten, Dec 2006
 */
#include <pcap.h>
#include <stdio.h>
#include <signal.h>

#define MAXPKT 16000	/* larger than any jumbogram */
static unsigned char buf[MAXPKT];

main(int argc, char *argv[]) {
    struct pcap_pkthdr ph;
    int c;
    int alter = 50;

    signal(SIGINT, SIG_IGN);

    c = fread(buf, sizeof(struct pcap_file_header), 1, stdin);
    c = fwrite(buf, sizeof(struct pcap_file_header), c, stdout);

    while ((c = fread(&ph, sizeof(struct pcap_pkthdr), 1, stdin)) > 0) {

	ph.caplen -= alter;
	ph.len -= alter;
	fwrite(&ph, sizeof(struct pcap_pkthdr), 1, stdout);
	if (fread(buf, ph.caplen+alter, 1, stdin) > 0) {
	    fwrite(buf+alter, ph.caplen, 1, stdout);
	    }
	else exit(1);
	}
    }
