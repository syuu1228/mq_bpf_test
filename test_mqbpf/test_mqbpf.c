/*-
 * Copyright (c) 2007 Seccuris Inc.
 * Copyright (c) 2007 Christian S.J. Peron
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/cpuset.h>

#include <net/bpf.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <net/ethernet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <err.h>
#include <pcap.h>
#include <assert.h>
#include <pthread.h>

struct bpf_thread_instance {
	pthread_t	thread;
	int 		rxqueue;
	int		txqueue;
	int		other;
	int		cpu;
	cpuset_t	cpuset;
	int		bpffd;
	u_int64_t	sum;	/* cycles spent processing packet data */
	u_int64_t	rsum;	/* cycles spent in syscalls after wakeup */
	u_int64_t	ssum;	/* cycles spent not sleep in event  loop */
	u_int64_t	psum;	/* cycles spent before buffer can be reclaimed */
	u_char		*bufa, *bufb;
	unsigned long	count;
	unsigned long	wrote;
	pcap_dumper_t	*dp;
	pcap_t		*p;
};

static char *ifname = NULL;
static struct bpf_thread_instance *instances;
static int rxqlen, txqlen, maxcpus;

int		bpf_open(void);
void		usage(void);

static struct ifreq	 ifr;
static char		*fflag;
#if 0
static unsigned long	 cflag;
#endif
static int		 Iflag;
static char		*iflag;
static int		 bflag = 32768;
static int		 wflag;
static int		 vflag;
static int		 zflag;
static int		 Tflag;
static int		 pflag;
static int		 Pflag;

#ifndef BPF_BUFMODE_ZBUF
/*
 * bpfnull uses certain constructs that depend on zero-copy definitions being
 * present in bpf.h even when running in normal buffer mode.  If the system
 * doesn't have these constructs, define them locally.
 */
struct bpf_zbuf {
	void	*bz_bufa;
	void	*bz_bufb;
	size_t	 bz_buflen;
};
#warning "BPF_BUFMODE_ZBUF not present, building without zero-copy support"
#endif

static int
handle_int(int sig __unused)
{
	int i;
	struct bpf_stat bs;
	double wrote = 0, throughput;
	u_int64_t	sum = 0;	/* cycles spent processing packet data */
	u_int64_t	rsum = 0;	/* cycles spent in syscalls after wakeup */
	u_int64_t	ssum = 0;	/* cycles spent not sleep in event  loop */
	u_int64_t	psum = 0;	/* cycles spent before buffer can be reclaimed */
	unsigned long	count = 0;
	u_int		recv = 0;
	u_int		drop = 0;

	for (i = 0; i < maxcpus; i++) {
		if (pthread_cancel(instances[i].thread) < 0) {
			perror("pthread_cancel");
			exit(-1);
		}
		if (pthread_join(instances[i].thread, NULL) < 0) {
			perror("pthread_join");
			exit(-1);
		}
		wrote += instances[i].wrote;
		sum += instances[i].sum;
		rsum += instances[i].rsum;
		ssum += instances[i].ssum;
		psum += instances[i].psum;
		count += instances[i].count;
		if (ioctl(instances[i].bpffd, BIOCGSTATS, &bs) < 0)
			err(-1, "BIOCGSTATS");
		recv += bs.bs_recv;
		drop += bs.bs_drop;
	}

	putchar('\n');
	printf("%lu cycles spent processing packets\n", sum);
	printf("%lu cycles spent in a syscall after wakeup\n", rsum);
	printf("%lu cycles spent not sleeping\n", ssum);
	printf("%lu cycles spent before buffer reclaims\n", psum);
	printf("%lu packets processed\n", count);
	wrote /= (double)(1024 * 1024);
	throughput = (wrote * 8) / 60;
	printf("wrote:%f MB throughput:%f Mbps\n",
		wrote, throughput);
	printf("%u packets received (BPF)\n", recv);
	printf("%u packets dropped (BPF)\n", drop);

	exit(0);
}

u_int64_t
rdtsc(void)
{
	u_int32_t high, low;

	__asm __volatile("rdtsc" : "=a" (low), "=d" (high));
	return (low | ((u_int64_t) high << 32));
}

static void
bpf_init_dumpfile(struct bpf_thread_instance *instance)
{
	char filename[strlen(fflag) + 4];

	if (wflag == 0)
		return;

	snprintf(filename, strlen(fflag) + 4, "%s.%x", fflag, instance->cpu);
	instance->p = pcap_open_dead(DLT_EN10MB, 0xffffU);
	instance->dp = pcap_dump_open(instance->p, filename);
	if (instance->dp == NULL) {
		pcap_perror(instance->p, filename);
		exit(-1);
	}
}

static void
bpf_process_packets(struct bpf_thread_instance *instance, struct bpf_zbuf *bz, char *bufname)
{
	struct pcap_pkthdr phd;
	int clen, hlen, i;
	u_char *b,*bp, *ep, *p, by;
#define bhp ((struct bpf_hdr *)bp)

	b = bp = bz->bz_bufa;
	ep = bp + bz->bz_buflen;
	while (bp < ep) {
		instance->count++;
#if 0
		if (cflag > 0 && packet_count > cflag)
			exit(0);
#endif
		if (pflag) {
			/*
			 * XXXCSJP this prefetch method needs to be
			 * re-visted
			 */
			__builtin_prefetch(bp + bhp->bh_datalen, 0, 3);
		}
		clen = bhp->bh_caplen;
		hlen = bhp->bh_hdrlen;
		p = (u_char *)bp + hlen;
		phd.ts.tv_sec = bhp->bh_tstamp.tv_sec;
		phd.ts.tv_usec = bhp->bh_tstamp.tv_usec;
		phd.caplen = phd.len = bhp->bh_datalen;
		if (Tflag) {
			for (i = 0; i < bhp->bh_datalen; i++)
				by = p[i];
			bp += BPF_WORDALIGN(clen + hlen);
			continue;
		}
		if (wflag) {
			pcap_dump((u_char *)instance->dp, &phd, p);
			if (ferror((FILE *)instance->dp)) {
				perror("dump.pcap");
				exit(-1);
			}
			fflush((FILE *)instance->dp);
		}
		instance->wrote += bhp->bh_caplen;
		bp += BPF_WORDALIGN(clen + hlen);
	}
}

static void
bpf_wait_for_fullbuf(struct bpf_thread_instance *instance)
{
	fd_set s_set, r_set;
	struct bpf_zbuf bz;
	char *pbuf;
	int n;
	struct bpf_zbuf_header *bzha, *bzhb;
	struct timeval tv;
	void *prev2, *prev;
	u_int64_t b, a, c, d, e, f;

	prev2 = prev = NULL;
	pbuf = malloc(bflag + 1);
	if (pbuf == NULL)
		err(1, "malloc");
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	FD_SET(instance->bpffd, &s_set);
        for (;;) {
		r_set = s_set;
		n = select(instance->bpffd + 1, &r_set, NULL, NULL, &tv);
		e = rdtsc();
		if (n < 0) {
			fprintf(stderr,"owned by select\n");
			err(1, "select failed");
		}
		if (vflag)
			(void) fprintf(stderr, "select wakeup\n");
		if (n != 0 && !FD_ISSET(instance->bpffd, &r_set) && vflag)
			printf("No timeout and fd is not ready!\n");
#ifdef BPF_BUFMODE_ZBUF
		if (zflag == 0) {
#endif
			c = rdtsc();
			n = read(instance->bpffd, pbuf, bflag);
			d = rdtsc();
			if (n < 0)
				err(1, "read failed");
			instance->psum += d - e;
			instance->rsum += d - c;
			bz.bz_bufa = pbuf;
			bz.bz_buflen = n;
			b = rdtsc();
			bpf_process_packets(instance, &bz, "W");
			a = rdtsc();
			instance->sum += a - b;
#ifdef BPF_BUFMODE_ZBUF
		} else {
			bzha = (struct bpf_zbuf_header *)instance->bufa;
			bzhb = (struct bpf_zbuf_header *)instance->bufb;
			if (n == 0) {
				c = rdtsc();
				if (ioctl(instance->bpffd, BIOCROTZBUF, &bz) < 0)
					err(1, "ioctl");
				d = rdtsc();
				instance->rsum += d - c;
				if (bz.bz_bufa == NULL) {
					if (vflag)
					printf("timeout no data\n");
					continue;
				}
			}
			assert(bzha->bzh_kernel_gen > bzha->bzh_user_gen ||
			    bzhb->bzh_kernel_gen > bzhb->bzh_user_gen);
			if (bzha->bzh_kernel_gen > bzha->bzh_user_gen) {
				bz.bz_bufa = instance->bufa;
				bz.bz_bufa += sizeof(struct bpf_zbuf_header);
				bz.bz_buflen = bzha->bzh_kernel_len;
				b = rdtsc();
				bpf_process_packets(instance, &bz, "A");
				a = rdtsc();
				instance->sum += a - b;
				instance->psum += a - e;
				bzha->bzh_user_gen++;
			} else if (bzhb->bzh_kernel_gen > bzhb->bzh_user_gen) {
				bz.bz_bufa = instance->bufb;
				bz.bz_bufa += sizeof(struct bpf_zbuf_header);
				bz.bz_buflen = bzhb->bzh_kernel_len;
				b = rdtsc();
				bpf_process_packets(instance, &bz, "B");
				a = rdtsc();
				instance->sum += a - b;
				instance->psum += a - e;
				bzhb->bzh_user_gen++;
			}
		}
#endif
		f = rdtsc();
		instance->ssum += f - e;
        }
}

int
bpf_open(void)
{
	char buf[32];
	int i, ret;

	for (i = 0; i < 8; i++) {
		snprintf(buf, sizeof(buf), "/dev/bpf%d", i);
		ret = open(buf, O_RDWR);
		if (ret != -1)
			break;
		else if (errno != EBUSY)
			(void) fprintf(stderr, "open %s: %s\n",
			    buf, strerror(errno));
	}
	return (ret);
}

void
usage()
{

	(void) fprintf(stderr, "usage: bpfnull [-ipPTwvz] [-b bufsize] "
	    "[-c limit] [-f file] -i interface\n");
	exit(0);
}

#ifdef BPF_BUFMODE_ZBUF
static int
bpf_zbuf_init(struct bpf_thread_instance *instance, struct bpf_zbuf *bz)
{
	int bmode;
	u_int zbufmax;

	if ((bflag % getpagesize()) != 0)
		errx(1, "-b must be multiple of system page size");
	bz->bz_buflen = bflag;
	instance->bufa = mmap(NULL, bz->bz_buflen, PROT_READ | PROT_WRITE,
	    MAP_ANON, -1, 0);
	if (instance->bufa == MAP_FAILED)
		err(1, "mmap(bufa)");
	instance->bufb = mmap(NULL, bz->bz_buflen, PROT_READ | PROT_WRITE,
	    MAP_ANON, -1, 0);
	if (instance->bufb == MAP_FAILED)
		err(1, "mmap(bufb)");
	bz->bz_bufa = instance->bufa;
	bz->bz_bufb = instance->bufb;
	bmode = BPF_BUFMODE_ZBUF;
	if (ioctl(instance->bpffd, BIOCSETBUFMODE, &bmode) < 0)
		err(1, "ioctl(BIOCGSETBUFMODE)");
	if (ioctl(instance->bpffd, BIOCGETZMAX, (caddr_t)&zbufmax) < 0) {
		err(1, "ioctl(BIOCGETZMAX)");
	}
	if (bz->bz_buflen > zbufmax) {
		printf("zbufmax is smaller than buflen:%d\n", zbufmax);
	}
	if (ioctl(instance->bpffd, BIOCSETZBUF, bz) < 0)
		err(1, "ioctl(BIOCSETZBUF)");
	if (vflag)
		(void) fprintf(stderr,
		    "DEBUG: bufa=%p bufb=%p\n", instance->bufa, instance->bufb);
	return (0);
}
#endif

static int
bpf_rbuf_init(struct bpf_thread_instance *instance)
{
	int v, bmode;

#ifdef BPF_BUFMODE_ZBUF
	bmode = BPF_BUFMODE_BUFFER;

	if (ioctl(instance->bpffd, BIOCGETBUFMODE, &bmode) < 0)
		err(1, "ioctl(BIOCGETBUFMODE)");
#endif
	for (v = bflag; v != 0; v >>= 1) {
		(void) ioctl(instance->bpffd, BIOCSBLEN, &v);
		if (ioctl(instance->bpffd, BIOCSETIF, &ifr) == 0)
			break;
	}
	if (ioctl(instance->bpffd, BIOCFLUSH, NULL) < 0)
		err(1, "ioctl(BIOCFLUSH)");
	return (0);
}

int bpf_thread(struct bpf_thread_instance *instance)
{
	struct bpf_zbuf bz;
	struct ifreq ifr;
	int opt;

	CPU_ZERO(&instance->cpuset);
	CPU_SET(instance->cpu, &instance->cpuset);
	if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1,
		sizeof(cpuset_t), &instance->cpuset) < 0) {
		perror("cpuset_setaffinity");
		exit(-1);
	}

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, iflag, sizeof(ifr.ifr_name));
	instance->bpffd = bpf_open();
	if (instance->bpffd < 0) {
		(void) fprintf(stderr, "bpfnull: no bpf device available\n");
		exit(-1);
	}
	if (vflag)
		(void) fprintf(stderr,
		    "DEBUG: obtained bpf fd=%d\n", instance->bpffd);
	if (fflag)
		bpf_init_dumpfile(instance);
#ifdef BPF_BUFMODE_ZBUF
	if (zflag) {
		if (vflag)
			(void) fprintf(stderr,
			    "DEBUG: bufmode=zerocopy\n");
		bzero(&bz, sizeof(bz));
		bpf_zbuf_init(instance, &bz);
		if (ioctl(instance->bpffd, BIOCSETIF, &ifr) < 0)
			err(1, "ioctl(BIOCSETIF)");
	} else {
#endif
		if (vflag)
			(void) fprintf(stderr,
			    "DEBUG: bufmode=buffer\n");
		bpf_rbuf_init(instance);
#ifdef BPF_BUFMODE_ZBUF
	}
#endif
	if (Iflag) {
		if (vflag)
			(void) fprintf(stderr,
			    "DEBUG: setting BIOCIMMEDIATE\n");
		opt = 1;
		if (ioctl(instance->bpffd, BIOCIMMEDIATE, &opt) < 0)
			err(1, "BIOCIMMEDIATE");
	}
	if (Pflag) {
		if (vflag)
			(void) fprintf(stderr,
			    "DEBUG: putting card into promiscuous "
			    "mode\n");
		if (ioctl(instance->bpffd, BIOCPROMISC, NULL) < 0)
			err(1, "BIOCPROMISC");
	}
	if (vflag)
		(void) fprintf(stderr,
		    "DEBUG: attaching to %s\n", iflag);

	if (ioctl(instance->bpffd, BIOCENAQMASK, NULL) < 0) {
		perror("enable qmask");
		return -1;
	}

	if (instance->rxqueue > -1) {
		if (ioctl(instance->bpffd, BIOCSTRXQMASK, &instance->rxqueue) < 0) {
			perror("rx qmask");
			return -1;
		}
	}

	if (instance->txqueue > -1) {
		if (ioctl(instance->bpffd, BIOCSTTXQMASK, &instance->txqueue) < 0) {
			perror("tx qmask");
			return -1;
		}
	}
	if (instance->other > -1) {
		if (ioctl(instance->bpffd, BIOCSTOTHERMASK, &instance->other) < 0) {
			perror("other qmask");
			return -1;
		}
	}

	instance->wrote = 0;


	bpf_wait_for_fullbuf(instance);
	return 0;
}

int
main(int argc, char *argv[])
{
	char ch;
	int i, s;
	struct sigaction action = {
		.sa_handler = (void (*)(int))handle_int,
		.sa_flags = 0
	};
	struct itimerval timer = {
		.it_interval = {
			.tv_sec = 0,
			.tv_usec = 0
		},
		.it_value = {
			.tv_sec = 60,
			.tv_usec = 0
		}
	};

	sigemptyset(&action.sa_mask);
	if (sigaction(SIGALRM, &action, NULL) < 0) {
		perror("sigaction");
		return -1;
	}
	if (setitimer(ITIMER_REAL, &timer, NULL) < 0) {
		perror("setitimer");
		return -1;
	}
	signal(SIGINT, (void *)handle_int);
	while ((ch = getopt(argc, argv, "b:c:f:hIi:pPTwvz")) != -1) {
		switch (ch) {
		case 'b':
			bflag = atoi(optarg);
			break;
#if 0
		case 'c':
			{
				char *r;
			cflag = strtoul(optarg, &r, 10);
			}
			break;
#endif
		case 'f':
			fflag = optarg;
			wflag = 1;
			break;;
		case 'i':
			iflag = optarg;
			break;
		case 'I':
			Iflag = 1;
			break;
		case 'p':
			pflag = 1;
			break;
		case 'P':
			Pflag = 1;
			break;
		case 'T':
			Tflag = 1;
			break;
		case 'w':
			wflag = 1;
			break;
		case 'v':
			vflag++;
			break;
#ifdef BPF_BUFMODE_ZBUF
		case 'z':
			zflag++;
			break;
#endif
		default:
			usage();
		}
	}
	if (iflag == NULL)
		usage();
	
	ifr.ifr_addr.sa_family = AF_LOCAL;
	strncpy(ifr.ifr_name, iflag, sizeof(ifr.ifr_name));
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

	maxcpus = MAX(rxqlen, txqlen);

	instances = (struct bpf_thread_instance *)
		calloc(maxcpus, sizeof(struct bpf_thread_instance));

	for (i = 0; i < maxcpus; i++) {
		instances[i].cpu = i;
		instances[i].rxqueue = -1;
		instances[i].txqueue = -1;
		instances[i].other = 0;
	}

	for (i = 0; i < rxqlen; i++) {
		ifr.ifr_queue_affinity_index = i;
		if (ioctl(s, SIOCGIFRXQAFFINITY, &ifr)) {
			perror("SIOCGIFRXQAFFINITY");
			return -1;
		}
		instances[ifr.ifr_queue_affinity_cpu].rxqueue = i;
	}

	for (i = 0; i < txqlen; i++) {
		ifr.ifr_queue_affinity_index = i;
		if (ioctl(s, SIOCGIFTXQAFFINITY, &ifr)) {
			perror("SIOCGIFTXQAFFINITY");
			return -1;
		}
		instances[ifr.ifr_queue_affinity_cpu].txqueue = i;
	}

	instances[0].other = 1;

	for (i = 0; i < maxcpus; i++) {
		if (pthread_create(&instances[i].thread, NULL, 
			(void *(*)(void *))bpf_thread, &instances[i]) < 0) {
			perror("pthread_create");
			return -1;
		}
	}

	for (i = 0; i < maxcpus; i++) {
		if (pthread_join(instances[i].thread, NULL) < 0) {
			perror("pthread_join");
			return -1;
		}
	}

	return (0);
}
