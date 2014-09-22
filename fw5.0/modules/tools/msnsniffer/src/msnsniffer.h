#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#ifdef WIN32
#include <direct.h>
#include <remote-ext.h>
#else
#include <netinet/in.h>
#include <unistd.h>
#endif
#include <time.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <ctype.h>

/* 4 bytes IP address */

typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* TCP Header */

    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

typedef struct tcp_header
{
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    unsigned th_seq; /* sequence number */
    unsigned th_ack; /* acknowledgement number */
	u_short off_unused; /* 4 bits data offset, 4 bits unused */
	union 
	{
		u_char byte;
		struct
		{
			unsigned unused: 2;
			unsigned th_fin: 1;
			unsigned th_syn: 1;
			unsigned th_rst: 1;
			unsigned th_push: 1;
			unsigned th_ack: 1;
			unsigned th_urg: 1;
		} bits;
	} th_flags;

    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
}tcp_header;

enum e_who_is_server
{
	unknown = 0,
	endpointA = 1,
	endpointB = 2
};

enum e_msn_conn_create
{
	create_no=0, 
	create_yes=1,
	create_replace=2 /* If found, delete data */
};

enum msn_conn_types
{
	type_unknown = 0, 
	type_notification_server = 1,
	type_switchboard = 2
};


struct msn_connection
{
	ip_address IP_A; 
	u_short port_A;
	ip_address IP_B;
	u_short port_B; 
	e_who_is_server whowserver;
	u_char *owner; 
	u_char **users; // If this is a switchboard, ID of users here
	int num_users;
        int connmap_timeout;
	enum msn_conn_types conn_type;
	struct msn_connection *previous, *next;
	char *log_full_path;
	int pending_A_length, pending_B_length;
	u_char *pending_A;
	u_char *pending_B;	
};

#define LINE_INCOMPLETE		-1
#define OUT_OF_MEMORY		-2
#define NOT_MSN			-3
#define CONN_DESTROYED		-4

#define BT_UNKNOWN		0
#define BT_TEXTPLAIN		1
#define BT_CONTROL		2
#define BT_PROFILE		3
#define BT_INITIAL_EMAIL	4
#define BT_NEW_EMAIL		5


#define PT_UNKNOWN			0
#define PT_MSN_MSG			1
#define PT_MSN_USR			2
#define PT_MSN_ANS			3
#define PT_MSN_IRO			4
#define PT_MSN_JOI			5
#define PT_MSN_OUT			6
#define PT_MSN_IGNORE			7  // Non interesting packets
#define PT_MSN_CAL			8
#define PT_MSN_BYE			9
#define PT_MSN_CHG			10
#define PT_MSN_ILN			11
#define PT_MSN_NLN			12
#define PT_MSN_LST			13
#define PT_MSN_PRP			14
#define PT_MSN_FLN			15
#define PT_MSN_SYN			16

#define HDR_CONTENT_TYPE	"Content-Type: "
#define HDR_TYPINGUSER		"TypingUser: "


int handler_msn_usr (u_char *raw, int length, ip_address source,
	u_short source_port, ip_address destination, u_short destination_port);
int handler_msn_chg (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port);
int handler_msn_ans (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port);
int handler_msn_iro (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port);
int handler_msn_joi (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port);		  
int handler_msn_out (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port);
int handler_msn_bye (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port);
int handler_msn_fln (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port);
int handler_msn_nln (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port);
int handler_msn_iln (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port);
int handler_msn_syn (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port);
int handler_msn_lst (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port);
int handler_msn_msg (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port);
int handler_msn_prp (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port);
int handler_msn_ignore (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port);

struct msn_connection *get_or_create_msn_connection (ip_address *source_ip, int source_port, 
	ip_address *target_ip, int target_port,
	enum e_msn_conn_create create);
void set_owner (struct msn_connection *conn, u_char *owner);
void set_as_server (struct msn_connection *conn, ip_address *ip, int port);
void add_user_to_sb (struct msn_connection *conn, u_char *user);
int is_from_server (struct msn_connection *conn, ip_address *ip, int port);
int remove_msn_connection (struct msn_connection *conn);
int is_from_A (struct msn_connection *conn, ip_address *ip, int port);
	
int log_event (u_char *nick, const char *fmt, ...);
int log_debug (int level, const char *fmt, ...);
int log_contact (u_char *nick, u_char *contact);
int log_profile (u_char *nick, u_char *payload, int length);
int log_switchboard_end (struct msn_connection *conn);
int log_switchboard_event (struct msn_connection *conn, const char *fmt, ...);	
int delete_contact_list (u_char *nick);
int delete_profile (u_char *nick);

u_char *urldecode (u_char *src);			
u_char *strcpymalloc (u_char **target, u_char * src);	
void free_array (u_char ***tokens);
int get_new_line_malloc (u_char **target, u_char *source, int length);
int get_tokens (u_char *line, u_char ***tokens, int max_tokens);
void dump_tokens (u_char **tokens);

int get_datalink_info (pcap_t *dh, char **name, int *offset);
int get_datalink_type (pcap_t *dh);

#define MAX_DIR_LENGTH 1024
#define MAX_VPRINTF 4096

extern char chatlogdir[MAX_DIR_LENGTH+1];
extern char debuglogdir[MAX_DIR_LENGTH+1];
extern int debug_level;
extern int daemonize;
extern u_char **line_tokens;
