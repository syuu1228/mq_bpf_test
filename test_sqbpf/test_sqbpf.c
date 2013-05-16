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

int		bpf_open(void);
void		usage(void);
u_int64_t	sum;	/* cycles spent processing packet data */
u_int64_t	rsum;	/* cycles spent in syscalls after wakeup */
u_int64_t	ssum;	/* cycles spent not sleep in event  loop */
u_int64_t	psum;	/* cycles spent before buffer can be reclaimed */

static struct ifreq	 ifr;
static pcap_dumper_t	*dp;
static pcap_t		*p;
static int		 bpffd = -1;
static char		*fflag = "-";
static unsigned long	 cflag;
static int		 Iflag;
static char		*iflag;
static int		 bflag = 32768;
static int		 wflag;
static int		 vflag;
static int		 zflag;
static int		 Tflag;
static int		 pflag;
static int		 Pflag;

static u_char		*bufa, *bufb;
static unsigned long		 packet_count;
static unsigned long		packet_wrote;

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
	struct bpf_stat bs;
	double wrote, throughput;

	putchar('\n');
	printf("%lu cycles spent processing packets\n", sum);
	printf("%lu cycles spent in a syscall after wakeup\n", rsum);
	printf("%lu cycles spent not sleeping\n", ssum);
	printf("%lu cycles spent before buffer reclaims\n", psum);
	printf("%lu packets processed\n", packet_count);
	wrote = (double)packet_wrote / (double)(1024 * 1024);
	throughput = (wrote * 8) / 60;
	printf("wrote:%f MB throughput:%f Mbps\n",
		wrote, throughput);
	if (ioctl(bpffd, BIOCGSTATS, &bs) < 0)
		err(-1, "BIOCGSTATS");

	printf("%u packets received (BPF)\n", bs.bs_recv);
	printf("%u packets dropped (BPF)\n", bs.bs_drop);

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
bpf_init_dumpfile(void)
{

	if (wflag == 0)
		return;
	p = pcap_open_dead(DLT_EN10MB, 0xffffU);
	dp = pcap_dump_open(p, fflag);
	if (dp == NULL) {
		pcap_perror(p, fflag);
		exit(1);
	}
}

#define CACHE_LINE_SIZE 32

static void
bpf_process_packets(struct bpf_zbuf *bz, char *bufname)
{
	struct pcap_pkthdr phd;
	int clen, hlen, i;
	u_char *b,*bp, *ep, *p, by;
#define bhp ((struct bpf_hdr *)bp)

	b = bp = bz->bz_bufa;
	ep = bp + bz->bz_buflen;
	while (bp < ep) {
		packet_count++;
		if (cflag > 0 && packet_count > cflag)
			exit(0);
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
			pcap_dump((u_char *)dp, &phd, p);
			if (ferror((FILE *)dp)) {
				perror("dump.pcap");
				exit(1);
			}
			fflush((FILE *)dp);
		}
		packet_wrote += bhp->bh_caplen;
		bp += BPF_WORDALIGN(clen + hlen);
	}
}

static void
bpf_wait_for_fullbuf(void)
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
	FD_SET(bpffd, &s_set);
        for (;;) {
		r_set = s_set;
		n = select(bpffd + 1, &r_set, NULL, NULL, &tv);
		e = rdtsc();
		if (n < 0) {
			fprintf(stderr,"owned by select\n");
			err(1, "select failed");
		}
		if (vflag)
			(void) fprintf(stderr, "select wakeup\n");
		if (n != 0 && !FD_ISSET(bpffd, &r_set) && vflag)
			printf("No timeout and fd is not ready!\n");
#ifdef BPF_BUFMODE_ZBUF
		if (zflag == 0) {
#endif
			c = rdtsc();
			n = read(bpffd, pbuf, bflag);
			d = rdtsc();
			if (n < 0)
				err(1, "read failed");
			psum += d - e;
			rsum += d - c;
			bz.bz_bufa = pbuf;
			bz.bz_buflen = n;
			b = rdtsc();
			bpf_process_packets(&bz, "W");
			a = rdtsc();
			sum += a - b;
#ifdef BPF_BUFMODE_ZBUF
		} else {
			bzha = (struct bpf_zbuf_header *)bufa;
			bzhb = (struct bpf_zbuf_header *)bufb;
			if (n == 0) {
				c = rdtsc();
				if (ioctl(bpffd, BIOCROTZBUF, &bz) < 0)
					err(1, "ioctl");
				d = rdtsc();
				rsum += d - c;
				if (bz.bz_bufa == NULL) {
					if (vflag)
					printf("timeout no data\n");
					continue;
				}
			}
			assert(bzha->bzh_kernel_gen > bzha->bzh_user_gen ||
			    bzhb->bzh_kernel_gen > bzhb->bzh_user_gen);
			if (bzha->bzh_kernel_gen > bzha->bzh_user_gen) {
				bz.bz_bufa = bufa;
				bz.bz_bufa += sizeof(struct bpf_zbuf_header);
				bz.bz_buflen = bzha->bzh_kernel_len;
				b = rdtsc();
				bpf_process_packets(&bz, "A");
				a = rdtsc();
				sum += a - b;
				psum += a - e;
				bzha->bzh_user_gen++;
			} else if (bzhb->bzh_kernel_gen > bzhb->bzh_user_gen) {
				bz.bz_bufa = bufb;
				bz.bz_bufa += sizeof(struct bpf_zbuf_header);
				bz.bz_buflen = bzhb->bzh_kernel_len;
				b = rdtsc();
				bpf_process_packets(&bz, "B");
				a = rdtsc();
				sum += a - b;
				psum += a - e;
				bzhb->bzh_user_gen++;
			}
		}
#endif
		f = rdtsc();
		ssum += f - e;
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
bpf_zbuf_init(struct bpf_zbuf *bz)
{
	int bmode, zmax;

	if ((bflag % getpagesize()) != 0)
		errx(1, "-b must be multiple of system page size");
	bmode = BPF_BUFMODE_ZBUF;
	if (ioctl(bpffd, BIOCSETBUFMODE, &bmode) < 0)
		err(1, "ioctl(BIOCGSETBUFMODE)");
#if 0
	if (ioctl(bpffd, BIOCGETZMAX, &zmax) < 0)
		err(1, "ioctl(BIOCGETZMAX)");
	if (bflag > zmax) {
		(void) fprintf(stderr,
			"buffer size is too big, truncated to %d\n",
			zmax);
		bflag = zmax;
	}
#endif
	bz->bz_buflen = bflag;
	bufa = mmap(NULL, bz->bz_buflen, PROT_READ | PROT_WRITE,
	    MAP_ANON, -1, 0);
	if (bufa == MAP_FAILED)
		err(1, "mmap(bufa)");
	bufb = mmap(NULL, bz->bz_buflen, PROT_READ | PROT_WRITE,
	    MAP_ANON, -1, 0);
	if (bufb == MAP_FAILED)
		err(1, "mmap(bufb)");
	bz->bz_bufa = bufa;
	bz->bz_bufb = bufb;
	if (ioctl(bpffd, BIOCSETZBUF, bz) < 0)
		err(1, "ioctl(BIOCSETZBUF)");
	if (vflag)
		(void) fprintf(stderr,
		    "DEBUG: bufa=%p bufb=%p\n", bufa, bufb);
	return (0);
}
#endif

static int
bpf_rbuf_init(void)
{
	int v, bmode;

#ifdef BPF_BUFMODE_ZBUF
	bmode = BPF_BUFMODE_BUFFER;

	if (ioctl(bpffd, BIOCGETBUFMODE, &bmode) < 0)
		err(1, "ioctl(BIOCGETBUFMODE)");
#endif
	for (v = bflag; v != 0; v >>= 1) {
		(void) ioctl(bpffd, BIOCSBLEN, &v);
		if (ioctl(bpffd, BIOCSETIF, &ifr) == 0)
			break;
	}
	if (ioctl(bpffd, BIOCFLUSH, NULL) < 0)
		err(1, "ioctl(BIOCFLUSH)");
	return (0);
}

int
main(int argc, char *argv[])
{
	int opt;
	struct bpf_zbuf bz;
	char ch;
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
		case 'c':
			{
				char *r;
			cflag = strtoul(optarg, &r, 10);
			}
			break;
		case 'f':
			fflag = optarg;
			wflag = 1;
			break;
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
	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, iflag, sizeof(ifr.ifr_name));
	bpffd = bpf_open();
	if (bpffd == -1) {
		(void) fprintf(stderr, "bpfnull: no bpf device available\n");
		exit(1);
	}
	if (vflag)
		(void) fprintf(stderr,
		    "DEBUG: obtained bpf fd=%d\n", bpffd);
	bpf_init_dumpfile();
#ifdef BPF_BUFMODE_ZBUF
	if (zflag) {
		if (vflag)
			(void) fprintf(stderr,
			    "DEBUG: bufmode=zerocopy\n");
		bzero(&bz, sizeof(bz));
		bpf_zbuf_init(&bz);
		if (ioctl(bpffd, BIOCSETIF, &ifr) < 0)
			err(1, "ioctl(BIOCSETIF)");
	} else {
#endif
		if (vflag)
			(void) fprintf(stderr,
			    "DEBUG: bufmode=buffer\n");
		bpf_rbuf_init();
#ifdef BPF_BUFMODE_ZBUF
	}
#endif
	if (Iflag) {
		if (vflag)
			(void) fprintf(stderr,
			    "DEBUG: setting BIOCIMMEDIATE\n");
		opt = 1;
		if (ioctl(bpffd, BIOCIMMEDIATE, &opt) < 0)
			err(1, "BIOCIMMEDIATE");
	}
	if (Pflag) {
		if (vflag)
			(void) fprintf(stderr,
			    "DEBUG: putting card into promiscuous "
			    "mode\n");
		if (ioctl(bpffd, BIOCPROMISC, NULL) < 0)
			err(1, "BIOCPROMISC");
	}
	if (vflag)
		(void) fprintf(stderr,
		    "DEBUG: attaching to %s\n", iflag);
	bpf_wait_for_fullbuf();
	return (0);
}
