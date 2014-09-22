/*
 * tfshow.c
 *
 * gcc -o tfshow tfshow.c -lpcap -lpthread
 *
*/

#define APP_NAME	"tfshow v1.3"

#define __USE_BSD         /* Using BSD IP header           */
#include <netinet/ip.h>   /* Internet Protocol             */
#define __FAVOR_BSD       /* Using BSD TCP header          */
#include <netinet/tcp.h>  /* Transmission Control Protocol */

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/ioctl.h>


/*#define SNAP_LEN 1518 */
#define SNAP_LEN 72

#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6

#define max_conn 1024

/* TCP Kill */
int kcont = 0;
int send_reset = 0;

/* Terminal cols */
int onlysyn = 0;
int t_cols = 80;
int t_rows = 24;
int disp_max = -1;
int disp_max2 = -1;
struct winsize ws;

/* Display time control */
void catch_alarm(int);

/* Total of bytes */
unsigned long int con_bytes = 0;
int SIZE_SLL = 0;

/* Control */
int lscon = 0;
int full_lock = 0;

/* Display in json format */
int json_ct = 1;
int json_out = 0;


/* Connection structure (by flow) */
typedef struct st_con_len st_con_len;
struct st_con_len {
    char source[32];
    char flow[256];
    long int length;
    long int length_old;
    float speed;
    float speed_average;
    int ttl;                /* TTL for speed 0 */
    int del;                /* delete by sort list - if TTL */
    int synct;              /* syn count */
    int speed_calc;
    st_con_len *next;
    st_con_len *last;
    st_con_len *sorted_addr;
};

/* Connection lists */
st_con_len *con_len = NULL;
st_con_len *con_len_first = NULL;
st_con_len *con_len_last = NULL;

/* Sorted conn list */
st_con_len *sorted_con_len = NULL;
st_con_len *sorted_con_len_first = NULL;


/* Connection Management List */
struct st_con_len *find_conlen(char *flow);
void del_conlen(st_con_len *del_con);
void upd_conlen(char *flow, char *src, int length);
void sort_conlen(st_con_len *so_con_len);
void calc_bandwidth(st_con_len *cl_con_len);
void show_st(void);


/* Clear screen */
void clear_screen(void) {
  ioctl(1, TIOCGWINSZ, &ws);
  if (ws.ws_col != t_cols) {
     t_cols = ws.ws_col;
     t_rows = ws.ws_row;
     printf("\033[2J");
  }
  printf("%c[%d;%df",0x1B, 0, 0);
}

/* Alarm for display updates */
void catch_alarm(int sig) {
  if (!json_out) clear_screen();
  show_st();
  alarm(1);
}

/* Bandwidth calc */
void calc_bandwidth(st_con_len *cl_con_len) {
  /* Current speed calcs */
  float len_dif = cl_con_len->length - cl_con_len->length_old;
  cl_con_len->length_old = cl_con_len->length;
  if (len_dif > 0) { 
     cl_con_len->speed = (float) ((len_dif * 8) / 1024);
     cl_con_len->ttl = 6;
  }
  else {
     cl_con_len->speed = 0;
     cl_con_len->synct = 0;
     cl_con_len->ttl--;
     if (cl_con_len->ttl < 0) cl_con_len->del = 1;
  }

  /* Average calcs */ 
  if (cl_con_len->speed_calc == 0) {
     cl_con_len->speed_average = cl_con_len->speed;
     cl_con_len->speed_calc++;
  }
  else {
     cl_con_len->speed_average = (float) cl_con_len->speed_average + cl_con_len->speed;
     cl_con_len->speed_average = (float) cl_con_len->speed_average / 2;
  }
}

/* Search for connection maps and return the pointer (total of bytes) */
struct st_con_len *find_conlen(char *flow) {
  struct st_con_len *fd_con_len = NULL;
  fd_con_len = con_len_first;
  for (; fd_con_len != NULL; fd_con_len = fd_con_len->next) {
     if (strcmp(flow, fd_con_len->flow) == 0) return fd_con_len;
  }
  return NULL;
}

/* Add a new connection or update connection length */
void upd_conlen(char *flow, char *src, int length) {

  struct st_con_len *fd_con_len = NULL;
  fd_con_len = find_conlen(flow);

  if (fd_con_len == NULL) {

     if (lscon >= max_conn) return;
     lscon++;

     /* Include a new connection */
     con_len = (st_con_len *) malloc(sizeof(st_con_len));

     strcpy(con_len->flow, flow);
     strcpy(con_len->source, src);
     con_len->length = length;
     con_len->ttl = 6;
     con_len->synct = 1;
     con_len->speed_calc = 0;
     con_len->length_old = 0;
     con_len->next = NULL;
     con_len->sorted_addr = NULL;

     if (con_len_first == NULL) {
        con_len_first = con_len;
        con_len->last = NULL;
     }
     else {
        con_len_last->next = con_len;
        con_len->last = con_len_last;
     }

     con_len_last = con_len;
  }
  else { 
     /* Update total of bytes */
     fd_con_len->synct++;
     fd_con_len->length = fd_con_len->length + length;
  }
  con_bytes += length;
}

/* delete connection with ttl 0 or last sorted list */
void del_conlen(st_con_len *del_con) {
  struct st_con_len *last_con = NULL;
  struct st_con_len *next_con = NULL;

  last_con = del_con->last;
  next_con = del_con->next;
  if (last_con == NULL) {
     if (del_con->next != NULL) {
        con_len_first = del_con->next;
        con_len_first->last = NULL;
     }
     else {
        con_len_last = NULL;
        con_len_first = NULL;
     }
  }
  else {
     if (del_con->next != NULL) {
        last_con->next = next_con;
        next_con->last = last_con;
     }
     else {
        last_con->next = NULL;
        con_len_last = last_con;
     }
  }
  lscon--;
  free(del_con);
}

/* Sorting by connections speed */
void sort_conlen(st_con_len *so_con_len) {
  int sorted = 0;
  float so_speed = 0;
  float sorted_speed = 0;
  st_con_len *last = NULL;
  st_con_len *temp = NULL;

  if (json_out == 0) {
     so_speed = so_con_len->speed;
     if (sorted_con_len_first != NULL) sorted_speed = sorted_con_len_first->speed;
  }
  else {
     so_speed = so_con_len->speed_average;
     if (sorted_con_len_first != NULL) sorted_speed = sorted_con_len_first->speed_average;
  }

  temp = (st_con_len *) malloc(sizeof(st_con_len));
  strcpy(temp->flow, so_con_len->flow);
  strcpy(temp->source, so_con_len->source);
  temp->del = so_con_len->del;
  temp->synct = so_con_len->synct;
  temp->speed = so_con_len->speed;
  temp->speed_average = so_con_len->speed_average;
  temp->length = so_con_len->length;
  temp->sorted_addr = so_con_len;

  if (sorted_con_len_first == NULL) {
    temp->next = NULL;
    sorted_con_len = temp;
    sorted_con_len_first = temp;
  }
  else {
 
    sorted_con_len = sorted_con_len_first;
    for (; sorted_con_len != NULL && sorted == 0; sorted_con_len = sorted_con_len->next) {
      if (json_out == 0) sorted_speed = sorted_con_len->speed;
      else sorted_speed = sorted_con_len->speed_average;

      if ((onlysyn == 0 && so_speed > sorted_speed) || (onlysyn == 1 && so_con_len->synct > sorted_con_len->synct)) {
         if (last == NULL) {
            temp->next = sorted_con_len_first;
            sorted_con_len_first = temp;
         }
         else {
            last->next = temp;
            temp->next = sorted_con_len;
         }
         sorted = 1;
      }
      last = sorted_con_len;
    }
    if (sorted == 0) {
      last->next = temp;
      temp->next = NULL;
    }
  }
}


/* Display stats */
void show_st(void) {

  char ulen[8];
  char hlen[256];
  float tot_speed = 0;
  long int auxlen = 0;
  long int sumpkt = 0;
  struct st_con_len *del_con = NULL;
  struct st_con_len *sw_con_len = NULL;

  int i = 0;
  int so_count = 0;
  int json_ctaux = 0;

  sw_con_len = con_len_first;
  sorted_con_len_first = NULL;

  /* Display area */
  full_lock = 1;
  int disp_count = 0;
  if (!json_out) {
     printf("\t\t\tConnections \t\t\t\t Speed cur / Speed Avg   Bytes\n\n");
     if (disp_max2 == -1) {
       if (t_rows > 24) {
          disp_max = t_rows / 2;
          disp_max = disp_max + (disp_max / 2);
          if (disp_max > 28) disp_max = 28;
       }
       else disp_max = 18;
     }
     else disp_max = disp_max2;
  }
  else disp_max = 15;

  /* Calc connection speed and make a sorted list */
  for (; sw_con_len != NULL; sw_con_len = sw_con_len->next) {

     /* Calc bandwidth */
     /* Add to sort list */
     calc_bandwidth(sw_con_len);
     sort_conlen(sw_con_len);

     sw_con_len->synct = 0;
     tot_speed += sw_con_len->speed;
  }

  sorted_con_len = sorted_con_len_first;
  for (; sorted_con_len != NULL; sorted_con_len = sorted_con_len->next) {

     if (!json_out) {
       /* Print stats in screen line */
       printf("\033[K");
       if (disp_count < disp_max) {
          if (sorted_con_len->length < 1025) {
             strcpy(ulen, "bytes   ");
             auxlen = sorted_con_len->length;
          }
          else {
             strcpy(ulen, "Kb");
             auxlen = sorted_con_len->length / 1024;
             if (auxlen > 1024) {
                if (auxlen < 1048576) {
                   strcpy(ulen, "Mb");
                   auxlen = sorted_con_len->length / 1048576;
                }
                else {
                   strcpy(ulen, "Gb");
                   auxlen = sorted_con_len->length / 1073741824;
                }
             }
          }

          sprintf(hlen, "%ld %s", auxlen, ulen);
          if (!onlysyn) printf("\n%s \t cur %-.2f / avg %-.2f Kbps   %s", sorted_con_len->flow, sorted_con_len->speed, sorted_con_len->speed_average, hlen);
          else {
             sumpkt += sorted_con_len->synct;
             printf("\n%s   \t pkt:%ld cur %-.2f / avg %-.2f Kbps   %s", sorted_con_len->flow, sorted_con_len->synct, sorted_con_len->speed, sorted_con_len->speed_average, hlen);
          }
          so_count++;
       }
     }
     else {
       /* Json output */
       if (json_ct > 3) {
          if (disp_count < disp_max) {
	     json_ctaux++;
             if (sorted_con_len == sorted_con_len_first) printf("[");
             else printf(",\n");
             printf("[\"%-.2f\", \"%s\", \"#%d\", \"#\", \"%s\"]", sorted_con_len->speed_average, sorted_con_len->source, rand()%999999, sorted_con_len->flow);
          }
       }
     }
     if (disp_count > 128 ||  sorted_con_len->del == 1) del_conlen(sorted_con_len->sorted_addr);

     if (del_con != NULL) free(del_con);
     del_con = sorted_con_len;
     disp_count++;
  }

  free(del_con);
  sorted_con_len = NULL;
  sorted_con_len_first = NULL;
  if (disp_count >= 128) so_count = disp_count;

  if (!json_out) {
     for (; disp_count < t_rows - 4; disp_count++) printf("\033[K\n");

     if (onlysyn) sprintf(hlen, "/ S pkts: %ld    ", sumpkt);
     else strcpy(hlen, "     ");

     printf("%c[%d;%df",0x1B, t_rows - 4, 0);
     printf("\033[K");
     printf("\n\nCur speed sum: %-8.2f Kbps      conn: %ld %s\n", tot_speed, so_count, hlen);

     // Adjust con_bytes to display
     if (con_bytes < 1025) {
        strcpy(ulen, "bytes   ");
        auxlen = con_bytes;
     }
     else {
        strcpy(ulen, "Kb");
        auxlen = con_bytes / 1024;
        if (auxlen > 1024) {
           if (auxlen < 1048576) {
              strcpy(ulen, "Mb");
              auxlen = con_bytes / 1048576;
           }
           else {
              strcpy(ulen, "Gb");
              auxlen = con_bytes / 1073741824;
           }
        }
     }

     sprintf(hlen, "%ld %s\t\t", auxlen, ulen);
     printf("Bytes (sum): %s\t\t\n", hlen);
  }
  else {
     /* Close Json string */
     if (json_ct > 3) {
        if (json_ctaux > 0) printf("]\n");
        json_ct = 0;
        exit(0);
     }
     json_ct++;
  }
  full_lock = 0;
}



/* TCP Kill functions */
/* http://www.programming-pcap.aldabaknocking.com/codesamples.html */

/* TCP RST by R.Stevens: pseudoheader and send_tcprst */

typedef struct pseudoheader {
  u_int32_t src;
  u_int32_t dst;
  u_char zero;
  u_char protocol;
  u_int16_t tcplen;
} tcp_phdr_t;

typedef unsigned short u_int16;
typedef unsigned long u_int32;

unsigned short in_cksum(unsigned short *addr,int len){

  register int sum = 0;
  u_short answer = 0;
  register u_short *w = addr;
  register int nleft = len;

  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
     *(u_char *)(&answer) = *(u_char *)w ;
     sum += answer;
  }

  sum = (sum >> 16) + (sum &0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return(answer);

}

int send_tcprst(int seq,  u_int32 src_ip, u_int32 dst_ip, u_int16 src_port, u_int16 dst_port, int tcp_len) {

  int one=1;
  int rawsocket=0;

  char packet[ sizeof(struct tcphdr) + sizeof(struct ip) + 1 ];
  struct ip *ipheader = (struct ip *)packet;
  struct tcphdr *tcpheader = (struct tcphdr *) (packet + sizeof(struct ip));
  tcp_phdr_t pseudohdr;

  char tcpcsumblock[ sizeof(tcp_phdr_t) + tcp_len ];

  /* Although we are creating our own IP packet with the destination address */
  /* on it, the sendto() system call requires the sockaddr_in structure */
  struct sockaddr_in dstaddr;  
			    
  memset(&pseudohdr,0,sizeof(tcp_phdr_t));
  memset(&packet, 0, sizeof(packet));
  memset(&dstaddr, 0, sizeof(dstaddr));   
  dstaddr.sin_family = AF_INET;
  dstaddr.sin_port = dst_port;
  dstaddr.sin_addr.s_addr = dst_ip;

  /* Get a raw socket to send TCP packets */  
  if ( (rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
      perror("TCP_RST_send():socket()"); 
      exit(1);
  }
     
  /* We need to tell the kernel that we'll be adding our own IP header */
  /* Otherwise the kernel will create its own. */
  if( setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){
      perror("TCP_RST_send():setsockopt()"); 
      exit(1);
  }
      
  /* IP Header */
  ipheader->ip_hl = 5;
  ipheader->ip_v = 4;
  ipheader->ip_tos = 0;
  ipheader->ip_len = htons( sizeof (struct ip) + sizeof (struct tcphdr) );
  ipheader->ip_off = 0;
  ipheader->ip_ttl = 64;
  ipheader->ip_p = 6;
  ipheader->ip_sum = 0;
  ipheader->ip_src.s_addr = src_ip;
  ipheader->ip_dst.s_addr = dst_ip;

  /* TCP Header */   
  tcpheader->th_seq = seq;
  tcpheader->th_x2 = 0;
  tcpheader->th_off = 5;
  tcpheader->th_flags = TH_RST;
  tcpheader->th_win = 0;
  tcpheader->th_urp = 0;
  tcpheader->th_sport = src_port;
  tcpheader->th_dport = dst_port;
  tcpheader->th_sum=0;

  pseudohdr.src = ipheader->ip_src.s_addr;
  pseudohdr.dst = ipheader->ip_dst.s_addr;
  pseudohdr.zero = 0;
  pseudohdr.protocol = ipheader->ip_p;
  pseudohdr.tcplen = htons( sizeof(struct tcphdr) );

  /* Copy header and pseudoheader to a buffer to compute the checksum */  
  memcpy(tcpcsumblock, &pseudohdr, sizeof(tcp_phdr_t));   
  memcpy(tcpcsumblock+sizeof(tcp_phdr_t),tcpheader, sizeof(struct tcphdr));

  /* Compute the TCP|IP checksum as the standard says (RFC 793|791) */
  tcpheader->th_sum = in_cksum((unsigned short *)(tcpcsumblock), sizeof(tcpcsumblock));
  ipheader->ip_sum = in_cksum((unsigned short *)ipheader, sizeof(struct ip));

  printf("RESET...  SRC: %15s:%-5d -> ", inet_ntoa(ipheader->ip_src), ntohs(tcpheader->th_sport));
  printf("DST: %15s:%-5d   ", inet_ntoa(ipheader->ip_dst), ntohs(tcpheader->th_dport));
  printf("Seq=%u \n", ntohl(tcpheader->th_seq));

  /* Send it through the raw socket */
  if ( sendto(rawsocket, packet, ntohs(ipheader->ip_len), 0,
      (struct sockaddr *) &dstaddr, sizeof (dstaddr)) < 0){
      return -1;
  }

  close(rawsocket);

  return 0;				    
}

/* End of TCP Kill functions */



/* Ethernet header struct */
struct sniff_ethernet {
     u_char  ether_dhost[ETHER_ADDR_LEN];
     u_char  ether_shost[ETHER_ADDR_LEN];
     u_short ether_type;
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};


/* UDP header */
struct sniff_udp {
        u_short uh_sport;               /* source port */
        u_short uh_dport;               /* destination port */
        u_short uh_ulen;                /* udp length */
        u_short uh_sum;                 /* udp checksum */
};

#define SIZE_UDP        8               /* length of UDP header */		


/* ICMP header */
struct sniff_icmp {
        u_int8_t  icmp_type;            /* type of message, see below */
        u_int8_t  icmp_code;            /* type sub code */
        u_int16_t icmp_cksum;           /* ones complement cksum of struct */
};

#define SIZE_ICMP       8               /* length of ICMP header */		



void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_app_usage(void);

void print_app_usage(void)
{
   printf("Usage: %s [Options]\n", APP_NAME);
   printf("\n");
   printf("Options:\n");
   printf("    -i <interface>       Ethernet interface \n");
   printf("    -p                   Disable promisc check.\n");
   printf("    -k                   Enable TCP Kill mode.\n");
   printf("    -f <pcap filter>     Define pcap filter.\n");
   printf("    -s                   Only tcp-syn pcap filter.\n");
   printf("    -r <nr rows>         Display rows.\n");
   printf("\n");

   return;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  const struct sniff_ethernet *ethernet;
  const struct sniff_ip *ip;
  const struct sniff_tcp *tcp;
  const struct sniff_udp *udp;
  const struct sniff_icmp *icmp;
  const char *payload;

  int size = 0;
  int size_ip, size_tcp, size_payload = 0;

  char flow[256] = "";
  char ip_src[32]="", ip_dst[32] = "", ip_proto[5]="";
  int port_src=0, port_dst=0;

  /* define ethernet header */
  ethernet = (struct sniff_ethernet*)(packet);
	
  /* define/compute ip header offset */
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET + SIZE_SLL);
  strcpy(ip_src, inet_ntoa(ip->ip_src));
  strcpy(ip_dst, inet_ntoa(ip->ip_dst));

  size_ip = IP_HL(ip) * 4;
  if (size_ip < 20) {
     //printf("   * Invalid IP header length: %u bytes\n", size_ip);
     return;
  }

  switch(ip->ip_p) {
    case IPPROTO_TCP:
       /* define/compute tcp header offset */
       tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + SIZE_SLL + size_ip);
       port_src = ntohs(tcp->th_sport);
       port_dst = ntohs(tcp->th_dport);
       strcpy(ip_proto, "tcp");

       size_tcp = TH_OFF(tcp)*4;
       if (size_tcp < 20) {
          //printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
          return;
       }
	
       /* define/compute tcp payload (segment) offset */
       payload = (u_char *)(packet + SIZE_ETHERNET + SIZE_SLL + size_ip + size_tcp);
       size_payload = (ntohs(ip->ip_len) - (size_ip + size_tcp));

       size = ntohs(ip->ip_len);

    break;

    case IPPROTO_UDP:
       /* define/compute udp header */
       udp = (struct sniff_udp *)(packet + SIZE_ETHERNET + SIZE_SLL + size_ip);
       port_src = ntohs(udp->uh_sport);
       port_dst = ntohs(udp->uh_dport);
       strcpy(ip_proto, "udp");

       /* define/compute udp payload (segment) */
       payload = (u_char *)(packet + SIZE_ETHERNET + SIZE_SLL + size_ip + SIZE_UDP);
       size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
       if (size_payload > ntohs(udp->uh_ulen)) size_payload = ntohs(udp->uh_ulen); 

       size = ntohs(ip->ip_len);
    break;

    case IPPROTO_ICMP:
       /* define/compute icmp header */
       icmp = (struct sniff_icmp *)(packet + SIZE_ETHERNET + SIZE_SLL + size_ip);
       strcpy(ip_proto, "icmp");

       /* define/compute icmp payload */
       payload = (u_char *)(packet + SIZE_ETHERNET + SIZE_SLL + size_ip + SIZE_ICMP);
       size_payload = ntohs(ip->ip_len);

       size = ntohs(ip->ip_len);
    break;

    default:
      return;
  }

  /* Connection flow */
  if (!send_reset) {
     if (full_lock == 0) {
        if (!onlysyn) sprintf(flow, "%4s %15s:%-5d    ->    %15s:%-5d", ip_proto, ip_src, port_src, ip_dst, port_dst);
        else sprintf(flow, "%4s %15s 	 	  <tcp-syn freq.>	", ip_proto, ip_src);
        upd_conlen((char *) flow, ip_src, size);
     }
  }
  else {
     /* Send TCP RST */
     if (kcont > ((t_rows / 2) - 4) || kcont == 0) {
        if (kcont > 0) sleep(1);
        kcont=0;
        printf("\033[2J");
        clear_screen();
        printf("\nKilling TCP Connections:\n\n");
     }
     if (ip->ip_p == IPPROTO_TCP && (tcp->th_flags == TH_PUSH || tcp->th_flags == TH_ACK)) {
	kcont++;
        send_tcprst( (int) tcp->th_ack, ip->ip_dst.s_addr, ip->ip_src.s_addr, tcp->th_dport, tcp->th_sport, size_ip );
        send_tcprst( (int) htonl(ntohl(tcp->th_seq)+1), ip->ip_src.s_addr,ip->ip_dst.s_addr, tcp->th_sport,tcp->th_dport, size_ip );
     }
  }

  return;
}


int main(int argc, char **argv)
{

  char *dev = NULL;			/* capture device name */
  char errbuf[PCAP_ERRBUF_SIZE];	/* error buffer */
  pcap_t *handle;			/* packet capture handle */

  int promisc = 1;
  int test_mode = 0;

  /* filter expression [3] */
  char filter_exp[1024] = "ip and (not (tcp[tcpflags] & (tcp-fin|tcp-rst) != 0))";

  struct bpf_program fp;		/* compiled filter program (expression) */
  bpf_u_int32 mask;			/* subnet mask */
  bpf_u_int32 net;			/* ip */

  /* check command-line */
  int i = 0, j = 0;
  int allowkill = 0;
  for (i = 1; i < argc; i++) {
     if (argv[i][0] == '-') {
       switch (argv[i][1]) {

          case 'i': dev = argv[i+1];             /* Define sniffer interface */
          break;

          case 'r': disp_max2 = atoi(argv[i+1]);  /* Define max number of rows */
          break;

          case 'p': promisc = 0;                 /* Disable promisc mode */
          break;

          case 'k': send_reset = 1;              /* Send tcp_reset */
          break;

	  case 'j':                              /* Json output for web stats */
		    json_out = 1;
		    send_reset = 0;
          break;
	  case 't':
	            test_mode = 1;
	  break;

          case 'f':                              /* PCAP filter */
	    allowkill = 1;
            strcat(filter_exp, " and (");
            for (j = i + 1; j < argc && argv[j][0] != '-'; j++) { 
              strcat(filter_exp, " "); 
	      strcat(filter_exp, argv[j]);
	    }
            strcat(filter_exp, " )");
	    if (j == i + 1) {
	      printf("Incomplete filter: %s\n\n", filter_exp);
              exit(EXIT_FAILURE);
	    }
          break;
          case 's':				/* Only syn capture */
            onlysyn = 1;
            strcat(filter_exp, " and (tcp[tcpflags] & (tcp-syn) != 0) and (tcp[tcpflags] & (tcp-ack) == 0)");
          break;

	  default:
            fprintf(stderr, "error: unrecognized command-line options\n");
	    printf("Invalid option: %s\n\n", argv[i]);
            print_app_usage();
            exit(EXIT_FAILURE);
	  break;
       }
     }
  } 

  if (dev == NULL) {
     /* find a capture device if not specified on command-line */
     dev = pcap_lookupdev(errbuf);
     if (dev == NULL) {
 	fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
	exit(EXIT_FAILURE);
     }
  }

  /* get network number and mask associated with capture device */
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
     fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
     net = 0;
     mask = 0;
     sleep(1);
  }


  /* print capture info */
  if (!json_out) {
    system("clear");
    printf("Device: %s\n", dev);
    if (promisc == 0) printf("Promisc interface: disabled\n");
    else printf("Promisc interface: enabled\n");

    if (allowkill && send_reset) printf("WARNING... TCP Kill mode enabled!\n");

    printf("\nFilter expression: %s\n\n", filter_exp);
    sleep(2);
  }

  /* open capture device */
  handle = pcap_open_live(dev, SNAP_LEN, promisc, 1000, errbuf);
  if (handle == NULL) {
     fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
     exit(EXIT_FAILURE);
  }

  if (strcmp(dev, "any") != 0) {
     /* make sure we're capturing on an Ethernet device [2] */
     if (pcap_datalink(handle) != DLT_EN10MB) {
         fprintf(stderr, "%s is not an Ethernet\n", dev);
         exit(EXIT_FAILURE);
     }
  }
  else SIZE_SLL = 2;

  if (onlysyn == 1 || json_out == 1) send_reset = 0;
  if (onlysyn == 0 && send_reset == 0) strcat(filter_exp, " and ((((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0) and greater 19)");
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
     fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
     exit(EXIT_FAILURE);
  }

  if (pcap_setfilter(handle, &fp) == -1) {
     fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
     exit(EXIT_FAILURE);
  }

  /* Alarm for display stats */
  if (!json_out) {
     printf("\033[2J");
     clear_screen();
  }

  if (test_mode) { 
     /* Return Ok on test mode */
     printf("Ok");
     exit(1);
  }
  else {
    if (send_reset) {
       if (allowkill) printf("\nKilling TCP Connections:\n\n");
       else {
          printf("ERROR:\n\tSpecify pcap filter to kill connections\n\tInclude option -f!\n\n");
          exit(EXIT_FAILURE);
       }
    }
    else {
       signal(SIGALRM, catch_alarm);
       alarm(1);
    }
  }

  /* now we can set our callback function */
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_freecode(&fp);
  pcap_close(handle);

  return 0;
}

