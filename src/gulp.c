/*
 * Sniff the network and optionally decapsulate as Cisco ERSPAN packets.
 *
 * Because of its improved buffering and scheduling strategy, Gulp
 * should out-perform traditional capture programs such as tcpdump when
 * the goal is to capture and write to disk.  A 2.6GHz Intel core2duo CPU
 * running RHEL5 (linux 2.6.18) can capture and save to disk 1Gb/s
 * dropping 0 packets (for full-to-medium size packets).
 *
 *-----------------------------------------------------------------------
 *
 * Author: Corey Satten,  corey @ u.washington.edu, May 2007 - Mar 2008
 *
 * See http://staff.washington.edu/corey/gulp for more information and the
 * latest version.
 *
 *         Copyright (C) 2007 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *-----------------------------------------------------------------------
 *
 * Usage: something like this to catch and decapsulate traffic from Cisco
 * remote span (ERSPAN) ports:
 *
 *     gulp -d ... > pcapfile
 *       or
 *     gulp -d ... | tcpdump -r - -w pcapfile ...
 *       or
 *     gulp -d ... | ngrep -I - -O pcapfile regexp ...
 *
 * or something like this to capture (and optionally filter) to a file:
 *
 *     gulp -f "optional pcap filter expression" ... > pcap_file
 *
 * or something like this to improve the performance of another sniffer:
 *
 *     tcpdump -i eth1 -s 0 -w - | gulp -c > pcap_file
 *
 * Gulp is threaded/buffered because writes to a file seem to sometimes
 * delay long enough to cause packet loss at the head of the pipeline even
 * though select would say the write will not block.
 *
 * Best results seem to come from confining the NIC interrupts and tcpdump
 * pipeline to CPU cores which share an L2 cache.  The former with
 *    # echo 3 > /proc/irq/#/smp_affinity   (see /proc/interrupts for #)
 * and the latter with
 *    # taskset -p 3 $$
 * see also http://staff.washington.edu/staff/corey/inter-core-benchmark
 *
 * The variables shared between threads are lock-free because each is
 * written only by one thread and careful coding ensures each thread
 * will always see a consistent-enough view to avoid problems.  This way
 * Gulp avoids locking overhead when the buffer is partly filled and
 * Gulp is working hardest at not dropping packets.  Traditional
 * signalling between threads could eliminate the short sleeps when the
 * buffer is either full or empty but these seem to consume negligible
 * time so why bother.
 */

#define _GNU_SOURCE
#ifdef linux
#include <syscall.h>
#endif
#include <unistd.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sched.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/wait.h>

#define gettid() syscall(__NR_gettid)	/* missing in headers? */
#define RINGSIZE 1024*1024*100	/* about 5 seconds of data at 200Mb/s */
#define MAXPKT 16384		/* larger than any jumbogram */
#define WRITESIZE 65536		/* usual write chunk size - must be 2^N */
#define GRE_HDRLEN 50		/* Cisco GRE encapsulation header size */
#define SNAP_LEN 65535		/* apparently what tcpdump uses for -s 0 */
#define READ_PRIO	-15	/* niceness value for Reader thread */
#define WRITE_PRIO	10	/* niceness value for Writer thread */
#define READER_CPU	1	/* assign Reader thread to this CPU */
#define WRITER_CPU	0	/* assign Writer thread to this CPU */
#define POLL_USECS	1000	/* ring full/empty poll interval */
#ifdef RHEL3
# define my_sched_setaffinity(a,b,c) sched_setaffinity(a, c)
#else
# define my_sched_setaffinity(a,b,c) sched_setaffinity(a, b, c)
#endif /* RHEL3 */
#define V_WIDTH		10	/* minimum size of -V ps status field */
#define TEMPLATE "/gulp.XXXXXX"	/* mktemp template for files in -o dir */

#define RMEM_MAX "/proc/sys/net/core/rmem_max"		/* system tuning */
#define RMEM_DEF "/proc/sys/net/core/rmem_default"	/* system tuning */
#define RMEM_SUG 4194304				/* suggested value */
FILE *procf; int rmem_def=RMEM_SUG, rmem_max=RMEM_SUG;	/* check tuning */

int  WriteSize = WRITESIZE;	/* desired size for aligned writes */
int  snap_len = SNAP_LEN;	/* requested limit on packet capture size */
int  d_snap_len = SNAP_LEN;	/* actual limit on packet capture size */
int  poll_usecs = POLL_USECS;	/* ring full/empty poll interval */
int  just_copy = 0;		/* read from stdin instead of eth# */
int  captured = 0;		/* number of packets captured for stats */
int  ignored = 0;		/* number of packets !decapsulated for stats */
int  maxbuffered = 0;		/* maximum number of bytes ring buffered */
int  ringsize = RINGSIZE;	/* ring buffer size */
int  gre_hdrlen = 0;		/* decapsulation header length */
char *dev = "eth1";		/* capture interface device name */
char *filter_exp = "";		/* decapsulation filter expression */
char *buf;			/* pointer to the big malloc'd ring buffer */
int  volatile start, end;	/* index of first, next byte in buf */
int  volatile boundary = -2;	/* index in buf to start a new output file */
int  push, eof;			/* flags for inter-thread communication */
char *progname;			/* argv[0] for error messages from threads */
int  warn_buf_full = 1;		/* unless reading a file, warn if buf fills */
pcap_t *handle = 0;		/* packet capture handle */
struct pcap_stat pcs;		/* packet capture filter stats */
int got_stats = 0;		/* capture stats have been obtained */
char *id = "@(#) Gulp RCS $Revision: 1.58-crox $"; /* automatically maintained */
int  check_eth = 1;		/* check that we are capturing from an Ethernet device */
int  would_block = 0;		/* for academic interest only */
int  check_block = 0;		/* use select to see if writes would block */
int  yield_if_blocking = 0;	/* experimental: may help on uniprocessors */
char *ps_stat_ptr = 0;		/* loc to display buf percentage used */
int  ps_stat_len = 0;		/* initial length of -V arg */
int  xlock = 0;			/* set if exclusive lock requested */
int  lockfd;			/* open descriptor to file to lock */
char *odir = 0;			/* requested output directory name */
char wfile[PATH_MAX];		/* output filename */
char *oname = "pcap";		/* requested output file name */
int  tflag = 0;			/* append timestamp to the file name */
int  filec = 0;			/* output file number */
struct pcap_file_header fh;	/* begins every pcap file */
int  split_after = 10;		/* start new output file after # ringbufs */
int  split_seconds = 0;		/* start new output file after # seconds */
time_t bdry_time = 0;           /* packet capture output file open time */
int  time_split = 0;		/* 1 when time() - bdry_time > split_seconds */
int  max_files = 0;		/* upper bound on filec */
int  volatile reader_ready = 0;	/* reader thread no longer needs root */
char *zcmd = NULL;              /* processes each savefile using a specified command */
int  zflag = 0;
static void child_cleanup(int); /* to avoid zombies, see below */


/*
 * put data onto the end of global ring buffer "buf"
 */
void
append(char *ptr, int len, int bdry)
    {
    static int just_wrapped = 0;
    static int wrap_cnt = 0;
    int avail, used;
    static int warned = -1;
    used = end - start; if (used < 0) used += ringsize;
    if (used > maxbuffered) maxbuffered = used;
    avail = ringsize - used;

    while (len >= avail) {		/* ring buffer is full, wait */
	if (warned<push) {
	    warned = push;
	    if (warn_buf_full)
		fprintf(stderr, "%s: ring buffer full\n", progname);
	    }
	usleep(poll_usecs);
	used = end - start; if (used < 0) used += ringsize;
	avail = ringsize - used;
	if (eof) return;
	}
    if (len > 0 && len < avail) {	/* ring buffer space available */
        if (bdry && (split_seconds != 0) && ((time(NULL) - bdry_time) >= split_seconds)) {
	    time_split = 1;
	    }
	if (end + len <= ringsize) {	  /* no wrap to beginning needed */
	    memcpy(buf+end, ptr, len);
	    }
	else {				  /* append wraps */
	    int c = ringsize-end;	
	    memcpy(buf+end, ptr, c);
	    memcpy(buf, ptr+c, len-c);
	    }
	if (end+len >= ringsize) {
	    end += len-ringsize;
	    just_wrapped = 1;
	    }
	else {
	    end += len;
	    }
	if (time_split || (just_wrapped && bdry)) {
	    if (just_wrapped) {
		wrap_cnt++;
	    just_wrapped = 0;
		}
	    if (odir && (wrap_cnt >= split_after || time_split)) {
		while (boundary >= 0) {	  /* last split still pending */
		    if (warned<push) {
			warned = push;
			if (warn_buf_full)
			    fprintf(stderr,"%s: ring buffer full\n", progname);
			}
		    usleep(poll_usecs);
		    }
		/*
		 * Tell Writer to start a new file.  Boundary is now < 0 so
		 * last split is complete.  Set boundary BEFORE appending file
		 * header; the write can't happen until the data is appended.
		 */
		boundary = end;
		wrap_cnt = 0;
		bdry_time = time(NULL);
		time_split = 0;
		if (!just_copy) append((char *)&fh, sizeof(fh), 0);
		}
	    }
	}
    }

#ifndef JUSTCOPY
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
    {
    struct pcap_pkthdr ph = *header;
    if (ph.caplen >= gre_hdrlen) {	/* sanity test */
	++captured;
	ph.caplen -= gre_hdrlen;
	ph.len -= gre_hdrlen;

	/*
	 * So that a capture file's layout is independent of the
	 * word size of the machine on which it's written, a packet
	 * record in a pcap file doesn't have a struct pcap_pkthdr
	 * at the beginning; it has a structure defined internally
	 * to libpcap, struct pcap_sf_pkthdr, which begins with another
	 * structure define internally to libpcap, struct pcap_timeval,
	 * with 32-bit tv_sec and tv_usec values.
	 */
	if (sizeof(long) > sizeof(int) && sizeof(int) > sizeof(short)) {
	    struct timeval_32 {
		int tv_sec;
		int tv_usec;
		} tv32;
	    tv32.tv_sec = ph.ts.tv_sec;
	    tv32.tv_usec= ph.ts.tv_usec;
	    append((char *)&tv32, sizeof(tv32), 0);
	    append((char *)&ph + sizeof(struct timeval),
		   sizeof(struct pcap_pkthdr) - sizeof(struct timeval), 0);
	    }
	else 
	    append((char *)&ph, sizeof(struct pcap_pkthdr), 0);
	append((char *)packet+gre_hdrlen, ph.caplen, 1);
	}
    else ++ignored;
    }
#endif /* JUSTCOPY */

void
cleanup(int signo)
    {
    eof = 1;
    if (just_copy == 1 || got_stats) return;
#ifndef JUSTCOPY
#ifndef RHEL3
    pcap_breakloop(handle);
#endif
    if (pcap_stats(handle, &pcs) < 0) {
	if (strcmp(dev, "-"))	/* ignore message if input is stdin */
	    (void)fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(handle));
	}
    else got_stats = 1;
#ifdef RHEL3
    pcap_close(handle);
#endif /* RHEL3 */
#endif /* JUSTCOPY */
    }

/*
 * This thread reads stdin or the network and appends to the ring buffer
 */
void *Reader(void *arg)
    {
#ifndef JUSTCOPY
    char errbuf[PCAP_ERRBUF_SIZE];	/* error buffer */
    struct bpf_program fp;		/* compiled filter program */
    bpf_u_int32 mask;			/* subnet mask */
    bpf_u_int32 net;			/* ip */
    int num_packets = -1;		/* number of packets to capture */
#endif
#ifdef CPU_SET
    int rtid = gettid();		/* reader thread id */
    cpu_set_t csmask;
    CPU_ZERO(&csmask);
    CPU_SET(READER_CPU, &csmask);
    if (my_sched_setaffinity(rtid, sizeof(cpu_set_t), &csmask) != 0) {
        fprintf(stderr, "%s: Reader could not set cpu affinity: %s\n",
	    progname, strerror(errno));
        }
    if (setpriority(PRIO_PROCESS, rtid, READ_PRIO) != 0) {
	fprintf(stderr, "%s: Reader could not set scheduling priority: %s\n",
	    progname, strerror(errno));
	}
#else
    replace with equivalent code for your OS or delete and run less optimally
#endif

#ifdef USE_SIGNAL
    signal(SIGINT, cleanup);
    signal(SIGPIPE, cleanup);
#else
    struct sigaction sa;
    sa.sa_handler = cleanup;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;			/* allow signal to abort pcap read */
    
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
#endif /* USE_SIGNAL */

    if (just_copy) {
	static char rbuf[MAXPKT];
	int c;
	reader_ready = 1;
	while (!eof && (c = read(0, rbuf, MAXPKT)) != 0) {
	    if (c > 0) append(rbuf, c, 1);
	    }
	}
#ifndef JUSTCOPY
    else {

    /*
     * get network number and mask associated with capture device
     * (needed to compile a bpf expression).
     */
    if (strcmp(dev,"-") && pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
	fprintf(stderr, "%s: Couldn't get netmask for dev %s: %s\n",
	    progname, dev, errbuf);
	net = 0;
	mask = 0;
    }

    /* open capture device */
    if (!strcmp(dev, "-")) {
	handle = pcap_open_offline(dev, errbuf);
#ifndef RHEL3
	int sfd = -2;
	if (handle) sfd = pcap_get_selectable_fd(handle);
	if (sfd >= 0 && lseek(sfd, 0, SEEK_CUR) >= 0) {
	    warn_buf_full = 0;		/* input is a file, don't warn */
	    }
#endif /* RHEL3 */
	}
    else
	handle = pcap_open_live(dev, d_snap_len, 1, 0, errbuf);
    if (handle == NULL) {
	fprintf(stderr, "%s: Couldn't open device %s: %s\n",
	    progname, dev, errbuf);
	exit(EXIT_FAILURE);
    }

    reader_ready = 1;

    /* make sure we're capturing on an Ethernet device */
    if (check_eth == 1 && pcap_datalink(handle) != DLT_EN10MB) {
	fprintf(stderr, "%s: %s is not an Ethernet\n", progname, dev);
	exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
	fprintf(stderr, "%s: Couldn't parse filter %s: %s\n",
	    progname, filter_exp, pcap_geterr(handle));
	exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
	fprintf(stderr, "%s: Couldn't install filter %s: %s\n",
	    progname, filter_exp, pcap_geterr(handle));
	exit(EXIT_FAILURE);
    }

    /*
     * emit pcap file header
     */

#ifndef RHEL3
    char tmpstr[] = "/tmp/gulp_hdr.XXXXXX";
    int tmpfd = mkstemp(tmpstr);
    if (tmpfd >= 0) {
	pcap_dumper_t *dump = pcap_dump_fopen(handle, fdopen(tmpfd,"w"));
	if (dump) pcap_dump_close(dump);
	tmpfd = open(tmpstr, O_RDONLY);	/* get pcap to create a header */
	if (tmpfd >= 0) read(tmpfd, (char *)&fh, sizeof(fh));
	if (tmpfd >= 0) close(tmpfd);
	unlink(tmpstr);
	fh.snaplen = snap_len;		/* snaplen after any decapsulation */
	}
#endif /* RHEL3 */
    if (fh.magic != 0xa1b2c3d4) {	/* if the above failed, do this */
	fprintf(stderr, "%s: using canned pcap header\n", progname);
	fh.magic = 0xa1b2c3d4;
	fh.version_major = 2;
	fh.version_minor = 4;
	fh.thiszone = 0;
	fh.sigfigs = 0;
	fh.snaplen = snap_len;
	fh.linktype = 1;
	}

    append((char *)&fh, sizeof(fh), 0);

    /* now we can set our callback function */
    pcap_loop(handle, num_packets, got_packet, NULL);

    fprintf(stderr, "\n%d packets captured\n", captured);
    if (ignored > 0) {
	fprintf(stderr, "%d packets ignored (too small to decapsulate)\n",
	    ignored);
	}
    if (got_stats) {
	(void)fprintf(stderr, "%d packets received by filter\n", pcs.ps_recv);
	(void)fprintf(stderr, "%d packets dropped by kernel\n", pcs.ps_drop);

	/*
	 * if packets dropped, check/warn if pcap socket buffer is too small
	 */
	if (pcs.ps_drop > 0) {
	    procf = fopen(RMEM_DEF, "r");
	    if (procf) {fscanf(procf, "%d", &rmem_def); fclose(procf);}
	    procf = fopen(RMEM_MAX, "r");
	    if (procf) {fscanf(procf, "%d", &rmem_max); fclose(procf);}
	    if (rmem_def < RMEM_SUG || rmem_max < RMEM_SUG) {
		fprintf(stderr, "\nNote %s may drop fewer packets "
		    "if you increase:\n  %s and\n  %s\nto %d or more\n\n",
		    progname, RMEM_MAX, RMEM_DEF, RMEM_SUG);
		}
	    }
	}
    if (check_block) {
	if (would_block)
	    fprintf(stderr, "select reports writes would have blocked\n");
	else
	    fprintf(stderr, "select reports writes would not have blocked\n");
	}
    /* cleanup */
    pcap_freecode(&fp);
#ifndef RHEL3
    pcap_close(handle);
#endif /* RHEL3 */

    }
#endif /* JUSTCOPY */
    fprintf(stderr, "ring buffer use: %.1lf%% of %d MB\n",
       	100.0*(double)maxbuffered/(double)(ringsize), ringsize/1024/1024);

    eof = 1;
    fflush(stderr);
    pthread_exit(NULL);
    }

/*
 * Post-process capture files after they have been rotated
 * (copied from tcpdump)
 */
static void
child_cleanup(int signo)
{
  wait(NULL);
}

void process_savefile(char filename[PATH_MAX]) {
    pid_t pid;

    if ( ! (zflag && strlen(filename)) )
        return;

    pid = fork();
    if ( pid == -1 ) {
        fprintf(stderr, "process_savefile: fork(): %s\n", strerror(errno));
        return;
    } else if (pid > 0 ) {
        /* parent process */
        return;
    }

    /* set to lowest priority */
#ifdef NZERO
    setpriority(PRIO_PROCESS, 0, NZERO - 1);
#else
    setpriority(PRIO_PROCESS, 0, 19);
#endif
    execlp(zcmd, zcmd, filename, (char *)NULL);
    /* exec*() return only on failure */
	fprintf(stderr, "process_savefile: execlp(%s, %s): %s\n", zcmd, filename, strerror(errno));
	exit(EXIT_FAILURE);
}

/*
 * Redirect standard output into a new capture file in the specified directory.
 *
 * In case Gulp is running setuid root, try to prevent a user from
 * overwriting system files.  This is accomplished by creating output files
 * with random temporary names in a directory to which the user has write
 * access and subsequently renaming them to names unlikely to cause trouble.
 */

int newoutfile(char *dir, int num) {
    char tfile[PATH_MAX];		/* output temp filename */
    char ofile[PATH_MAX];		/* output real filename */
    if (access(dir, W_OK) != 0) {
	if (access(dir, F_OK) != 0) {
	    fprintf(stderr, "%s: -o dir does not exist: '%s'\n",
		progname, dir);
	    return (0);
	    }
	fprintf(stderr, "%s: can't create files in '%s'\n", progname, dir);
	return (0);
	}
    snprintf(tfile, sizeof(tfile), "%s%s", dir, TEMPLATE);
    if (tflag) {
//    	snprintf(ofile, sizeof(ofile), "%s/%s%lld.%03d", dir, oname, (long long int)time(NULL), num);
        char outstr[200];
        time_t t;
        struct tm *tmp;
        const char* fmt = "%Y%m%d%H%M%S";

        t = time(NULL);
        tmp = gmtime(&t);
        if (tmp == NULL) {
            perror("gmtime error");
            exit(EXIT_FAILURE);
        }

        if (strftime(outstr, sizeof(outstr), fmt, tmp) == 0) {
            fprintf(stderr, "strftime returned 0");
            exit(EXIT_FAILURE);
        }

        snprintf(ofile, sizeof(ofile), "%s/%s_%s.pcap", dir, oname, outstr);
	}
    else {
    	snprintf(ofile, sizeof(ofile), "%s/%s%03d.pcap", dir, oname, num);
	}
    int tmpfd = mkstemp(tfile);
    fchown(tmpfd, getuid(), -1);	/* in case running setuid */
    if (tmpfd >= 0) {
	if (freopen(tfile, "w", stdout) == NULL) {
	    fprintf(stderr, "%s: can't create output file: '%s'\n",
		progname, tfile);
	    return (0);
	    }
	dup2(tmpfd, fileno(stdout));	/* try to use the initial fd */
	close(tmpfd);
	rename(tfile, ofile);
	if (odir) process_savefile(wfile);
	/* wfile = ofile; */
	snprintf(wfile, sizeof(wfile), "%s", ofile);
	return (1);
	}
    else {
	fprintf(stderr, "%s: can't create: '%s'\n", progname, tfile);
	return(0);
	}
    return (0);				/* some error */
    }

/*
 * This thread copies the ring buffer to stdout in WriteSize chunks
 * or every second (or so) whichever happens first.
 */
void *Writer(void *arg)
    {
    int n;
    int used;
    int writesize;
    int done = 0;
    int pushed = 0;			/* value of "push" at last write  */
#ifdef CPU_SET
    int wtid = gettid();		/* Writer thread id */
    cpu_set_t csmask;
    CPU_ZERO(&csmask);
    CPU_SET(WRITER_CPU, &csmask);
    if (my_sched_setaffinity(wtid, sizeof(cpu_set_t), &csmask) != 0) {
        fprintf(stderr, "%s: Writer could not set cpu affinity: %s\n",
	    progname, strerror(errno));
        }
    if (setpriority(PRIO_PROCESS, wtid, WRITE_PRIO) != 0) {
	fprintf(stderr, "%s: Writer could not set scheduling priority: %s\n",
	    progname, strerror(errno));
	}
#else
    replace with equivalent code for your OS or delete and run less optimally
#endif /* CPU_SET */
    
    if (geteuid()!=getuid()) {
	while (!reader_ready) usleep(poll_usecs);
	seteuid(getuid());		/* drop setuid privilege */
	}

    if (tflag) {
	if (max_files && max_files != 1000) {
	    fprintf(stderr, "%s: -W will be set to 1000 because -t is also set\n", progname); 
	    }
	max_files = 1000;
	}

    if (odir && !newoutfile(odir, filec++)) {
	exit(1);
	}

    while (!done) {
	used = end - start; if (used < 0) used += ringsize;
	if (start & (WriteSize-1))
	    writesize = WriteSize - (start & (WriteSize-1)); 	/* re-align */
	else
	    writesize = WriteSize;
	while (used < WriteSize) {
	    if (eof) {
		done = 1;
		used = end - start; if (used < 0) used += ringsize;
		writesize = used;
		break;
		}
	    else if (push > pushed+1) {
		writesize = used;
		if (used) break;
		}
	    usleep(poll_usecs);
	    used = end - start; if (used < 0) used += ringsize;
	    }
	n = ringsize - start;		/* short write at end of ring? */
	if (n < writesize) writesize = n;	/* write remainder next loop */
	if (check_block) {
	    /*
	     * this is mostly of academic interest
	     */
	    fd_set w_set;
	    struct timeval timeout;
	    timeout.tv_sec = 0;
	    timeout.tv_usec = 0;
	    FD_ZERO(&w_set);
	    FD_SET(1, &w_set);
	    if (select(2, NULL, &w_set, NULL, &timeout) != -1) {
		if (!FD_ISSET(1, &w_set)) {
		    would_block = 1;
		    if (yield_if_blocking) {
			writesize = 0;	/* next iteration will try again */
			sched_yield();
			}
		    }
		}
	    }
	if (writesize > 0) {
	    if (start < boundary && start+writesize >= boundary) {
		writesize = boundary - start;
		}
	    writesize = write(1, buf+start, writesize);
	    }
	if (writesize == -1 && errno == EINTR) writesize = 0;
	if (writesize < 0) {
	    fprintf(stderr, "%s: fatal write error: %s\n",
	       	progname, strerror(errno));
	    eof = 1;
	    fflush(stderr);
	    pthread_exit(0);
	    }
	start += (start+writesize >= ringsize) ? writesize-ringsize : writesize;
	if (start == boundary) {
	    if (max_files && filec >= max_files) filec = 0;
	    newoutfile(odir, filec++);
	    boundary = -2;
	    }
	pushed = push;
	}
    if (odir) process_savefile(wfile);
    pthread_exit(NULL);
    }

void
usage() {
    fprintf(stderr,
    "\n"
    "Usage: %s [--help | options]\n"
    "    --help\tprints this usage summary\n"
    "    supported options include:\n"
#ifdef JUSTCOPY
    "    (This binary was compiled with JUSTCOPY so some options are unavailable)\n"
#else  /* JUSTCOPY */
    "      -d\tdecapsulate Cisco ERSPAN GRE packets (sets -f value)\n"
    "      -f \"...\"\tspecify a pcap filter - see manpage and -d\n"
    "      -i eth#|-\tspecify ethernet capture interface or '-' for stdin\n"
    "      -s #\tspecify packet capture \"snapshot\" length limit\n"
    "      -F\tskip the interface type (Ethernet) check\n"
#endif /* JUSTCOPY */
    "      -r #\tspecify ring buffer size in megabytes (1-1024)\n"
    "      -c\tjust buffer stdin to stdout (works with arbitrary data)\n"
    "      -x\trequest exclusive lock (to be the only instance running)\n"
    "      -X\trun even when locking would forbid it\n"
    "      -v\tprint program version and exit\n"
    "      -Vx...x\tdisplay packet loss and buffer use - see manpage\n"
    "      -p #\tspecify full/empty polling interval in microseconds\n"
    "      -q\tsuppress buffer full warnings\n"
    "      -z #\tspecify write blocksize (even power of 2, default 65536)\n"
    "    for long-term capture\n"
    "      -o dir\tredirect pcap output to a collection of files in dir\n"
    "      -n name\tfilename (default: pcap)\n"
    "      -t\tappend a timestamp to the filename\n"
    "      -C #\tlimit each pcap file in -o dir to # times the (-r #) size\n"
    "      -G #\trotates the pcap file every # seconds\n"
    "      -W #\toverwrite pcap files in -o dir rather than start #+1 (max_files)\n"
    "      -Z postrotate-command\trun 'command file' after each rotation\n"
    "    and some of academic interest only:\n"
    "      -B\tcheck if select(2) would ever have blocked on write\n"
    "      -Y\tavoid writes which would block\n"
    "\n", progname);
    }

/*
 * This thread starts the other two and then wakes every half second
 * to increment a variable the writer uses to decide if it should flush.
 * Flushing greatly facilitates interactive use and testing tcpdump filters.
 */
int main(int argc, char *argv[], char *envp[])
    {
    pthread_t threads[2];
    int rc, t, c, errflag=0;
    extern char *optarg;
    extern int optind;
    int bitmask;

    start = end = eof = 0;
    progname = argv[0];
#ifdef JUSTCOPY
    just_copy = 1;
#endif

    /* pick up default interface to sniff from ENV if present */
    if (getenv("CAP_IFACE")) dev = getenv("CAP_IFACE");

    if (argc > 1 && strcmp(argv[1], "--help") == 0) ++errflag; else
#ifndef JUSTCOPY
    while ((c = getopt(argc, argv, "BFXYcdqtvxf:i:p:r:s:z:V:o:n:C:G:W:Z:")) != EOF)
#else  /* JUSTCOPY */
    while ((c = getopt(argc, argv, "BXYcqtvxp:r:z:V:o:n:C:G:W:Z:")) != EOF)
#endif /* JUSTCOPY */
	{
	switch (c) {
	    case 'B':
		check_block = 1;	/* use select to avoid write blocking */
		break;
	    case 'F':
		check_eth = 0;	        /* don't check that we are capturing from an */
		break;                  /* Ethernet device */
	    case 'Y':
		check_block = 1;
		yield_if_blocking = 1;	/* don't issue blocking writes */
		break;
	    case 'V':			/* produce periodic drop,ring stats */
		ps_stat_ptr = optarg;
		if (ps_stat_ptr[0] == '-') {
		    fprintf(stderr, "%s: %s is suspicious as argument of -V\n",
			progname, ps_stat_ptr);
		    errflag++;
		    }
		ps_stat_len = strlen(ps_stat_ptr);
		break;
	    case 'c':
		just_copy = 1;		/* just read from stdin and buffer */
		break;
	    case 'd':
		gre_hdrlen = GRE_HDRLEN;/* decapsulate Cisco GRE */
		filter_exp = "proto gre";
		break;
	    case 'f':
		filter_exp = optarg;
		break;
	    case 'i':			/* specify ethernet device name */
		dev = optarg;
		break;
	    case 'p':			/* specify polling sleep u_secs */
		t = atoi(optarg);
		if (t < 0 || t > 1000000) {
		    fprintf(stderr, "%s: -p number must be 0-1000000\n",
			progname);
		    ++errflag;
		    }
		else poll_usecs = t;
		break;
	    case 'q':			/* warnings can be annoying */
		warn_buf_full = 0;
		break;
	    case 'r':
		t = atoi(optarg);	/* specify ring size in MB */
		if (t < 1 || t > 1024) {
		    fprintf(stderr, "%s: -r number must be 1-1024\n",
			progname);
		    ++errflag;
		    }
		else ringsize = t * 1024*1024;
		break;
	    case 's':			/* specify snapshot length */
		t = atoi(optarg);
		if (t <= 0 || t > SNAP_LEN) t = SNAP_LEN;
		snap_len = t;
		break;
	    case 'v':
		fprintf(stderr, "%s\n", id+5);
		exit(0);
		break;
	    case 'x':
		xlock = 1;		/* request exclusive lock */
		break;
	    case 'X':
		xlock = -1;		/* disregard locking conflicts */
		break;
	    case 'z':
		t = atoi(optarg);	/* specify goal write size 2^n */
		for (bitmask=1; bitmask<=65536; bitmask*=2) {
		    if (t == bitmask) WriteSize = t;
		    }
		if (WriteSize != t) {
		    fprintf(stderr, "%s: -z number must be a power of 2\n",
			progname);
		    errflag++;
		    }
		break;
	    case 't':
		tflag = 1;
		break;
	    case 'n':
		oname = optarg;
		break;
	    case 'o':
		odir = optarg;
		if (strlen(odir) >= PATH_MAX-strlen(TEMPLATE)-1) {
		    fprintf(stderr, "%s: -o name too long: %s\n",
			progname, odir);
		    errflag++;
		    }
		break;
	    case 'C':
		split_after = atoi(optarg);
		if (split_after < 1) {
		    fprintf(stderr, "%s: -C # must be 1 or greater\n",
			progname);
		    errflag++;
		    }
		break;
	    case 'G':
		split_seconds = atoi(optarg);
		if (split_seconds < 1) {
		    fprintf(stderr, "%s: -G # must be 1 or greater\n",
			progname);
		    errflag++;
		    }
		break;
	    case 'W':
		max_files = atoi(optarg);
		if (max_files < 1) {
		    fprintf(stderr, "%s: -W # must be 1 or greater\n",
			progname);
		    errflag++;
		    }
		break;
	    case 'Z':
		zcmd = optarg;
                zflag = 1;
		break;
	    default:
		errflag++;
		break;
	    }
	}
    if (errflag || optind < argc) {
	usage();
	exit(1);
	}

    /* to avoid zombies when using -Z */
    (void)sigset(SIGCHLD, child_cleanup);

    /*
     * if -d is spcified, -s refers to decapsulated sizes, make it happen
     */
    d_snap_len = snap_len + gre_hdrlen;
    if (d_snap_len <= 0 || d_snap_len > SNAP_LEN) d_snap_len = SNAP_LEN;

    if (isatty(1) && !just_copy && !odir) {
	fprintf(stderr, "%s:\tSending raw pcap data to a terminal is not a "
	    "good idea.\n\tIf you really want to do that, pipe %s through "
	    "cat but you\n\tprobably want to redirect stdout to a file or "
	    "another program instead.\n\tPerhaps you meant to pipe into "
	    "'tcpdump -r-' or 'ngrep -I-' ?\n", progname, progname);
	if (argc == 1) usage();
	exit(1);
	}

    /*
     * Advisory locking logic
     */
    if ((lockfd = open("/proc/self/exe", O_RDONLY)) < 0) {
	fprintf(stderr, "%s: Warning: couldn't open lockfile so not locking\n",
	    progname);
	}
    else {
	if (flock(lockfd, ((xlock==1 ? LOCK_EX : LOCK_SH) | LOCK_NB)) == -1) {
	    if (xlock < 0) {
		fprintf(stderr, "%s: Warning: overriding locking\n",
		    progname);
		}
	    else {
		fprintf(stderr, "%s: Exiting due to lock conflict\n",
		    progname);
		exit(1);
		}
	    }
	}

    buf = malloc(ringsize+1);
    if (!buf) {
	fprintf(stderr, "%s: Malloc failed, exiting\n", progname); exit(1);
	}
    if (mlock(buf, ringsize+1) != 0) {
	fprintf(stderr, "%s: Warning: could not lock ring buffer into RAM\n",
	    progname);
	}

    rc = pthread_create(&threads[0], NULL, &Reader, NULL);
    if (rc){
	fprintf(stderr, "%s: pthread_create error\n", progname);
	exit(1);
	}

    rc = pthread_create(&threads[1], NULL, &Writer, NULL);
    if (rc){
	fprintf(stderr, "%s: pthread_create error\n", progname);
	exit(1);
	}

    while (!eof) {
	usleep(500000);
	push += 1;
	/*
	 * emit some stats which may be useful while testing
	 * if argument to -V is big enough to write into, do so
	 * else write to stdout.
	 */
	if (ps_stat_ptr) {
	    char sbuf[V_WIDTH+1];
	    int drop_symb = 0;
	    int used = end - start; if (used < 0) used += ringsize;
#ifndef JUSTCOPY
	    if (handle && pcap_stats(handle, &pcs) >= 0) {
		int d = pcs.ps_drop;
		/* count how many decimal digits are in the drop count */
		for (drop_symb = 0; drop_symb < 9; ++drop_symb) {
		    if (d == 0) break;
		    d /= 10;
		    }
		}
#endif /* JUSTCOPY */
	    if (ps_stat_len >= V_WIDTH) {	/* put stats in arg list */
		sprintf(sbuf, "%1.1d %.0lf,%.0lf%%",
		    drop_symb,	/* a digit from 0-9 */
		    100.0*(double)used/(double)(ringsize),
		    100.0*(double)maxbuffered/(double)(ringsize));
		sprintf(ps_stat_ptr, "%-*s", ps_stat_len, sbuf);
		}
	    else {				/* puts stats on stderr */
		fprintf(stderr,
		    "pkts dropped: %d, ring buf: %.1lf%%, max: %.1lf%%\n",
		    (drop_symb > 0 ? pcs.ps_drop : 0),
		    100.0*(double)used/(double)(ringsize),
		    100.0*(double)maxbuffered/(double)(ringsize));
		}
	    }
	}

    fflush(stderr);
    pthread_exit(NULL);
    }
