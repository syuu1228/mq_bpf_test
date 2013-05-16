#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_var.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	struct	ifreq ifr;
	int s, rxqlen, txqlen, i;

	if (argc < 2) {
		printf("usage: %s [ifname]\n", argv[0]);
		return -1;
	}

	ifr.ifr_addr.sa_family = AF_LOCAL;
	strncpy(ifr.ifr_name, argv[1], sizeof(ifr.ifr_name));
	s = socket(ifr.ifr_addr.sa_family, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("socket");
		return -1;
	}

	if (ioctl(s, SIOCGIFQLEN, &ifr)) {
		perror("SIOCGIFQLEN");
		return -1;
	}
	rxqlen = ifr.ifr_rxqueue_len;
	txqlen = ifr.ifr_txqueue_len;

	printf("\trxqueue len=%d affinity=[", rxqlen);
	for (i = 0; i < rxqlen; i++) {
		ifr.ifr_queue_affinity_index = i;
		if (ioctl(s, SIOCGIFRXQAFFINITY, &ifr)) {
			perror("SIOCGIFRXQAFFINITY");
			return -1;
		}
		printf(" %d:%d", ifr.ifr_queue_affinity_index,
			ifr.ifr_queue_affinity_cpu);
	}
	printf(" ]\n");

	printf("\ttxqueue len=%d affinity=[", txqlen);
	for (i = 0; i < txqlen; i++) {
		ifr.ifr_queue_affinity_index = i;
		if (ioctl(s, SIOCGIFTXQAFFINITY, &ifr)) {
			perror("SIOCGIFTXQAFFINITY");
			return -1;
		}
		printf(" %d:%d", ifr.ifr_queue_affinity_index,
			ifr.ifr_queue_affinity_cpu);
	}
	printf(" ]\n");
	close(s);
	return 0;
}
