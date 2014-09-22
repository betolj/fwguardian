#include "msnsniffer.h"


char chatlogdir[MAX_DIR_LENGTH+1]="";
char auxchatlogdir[MAX_DIR_LENGTH+1]="";
char debuglogdir[MAX_DIR_LENGTH+1]="";
int daemonize=0;

const char *currentversion = "1.2.1";

int data_offset = -1;

char *devname=NULL;
int promisc=0;
int with_proxy = 0;
char proxy_addr[255];
char last_msg[20480] = "";

int use_filter = 0;
char filter_app[1024] = "ip and tcp";

void show_help (void);


// Include date information into log chat
char sdate[30] = "";
time_t time_start = time(NULL);
time_t time_elapsed = time(NULL);
void date_logchat(char logdir[]) {
        size_t i;
        struct tm tim;
        time_t now;
        struct stat st;

        now = time(NULL);
        tim = *(localtime(&now));
        i = strftime(sdate,30,"/%d%b%Y/",&tim);

	strcpy (chatlogdir, logdir);
        strcat (chatlogdir, sdate);

	mkdir (logdir,0700);
        if (stat(chatlogdir, &st) != 0) mkdir (chatlogdir,0700);
}
	
int analyze_packet (u_char *data)
{
	struct msn_cmd
	{
		const char *command;
		int type;
	} 
	cmds[]= { 
			{ "MSG ", PT_MSN_MSG},
			{ "USR ", PT_MSN_USR},
			{ "ANS ", PT_MSN_ANS},
			{ "IRO ", PT_MSN_IRO},
			{ "JOI ", PT_MSN_JOI},
			{ "OUT ", PT_MSN_OUT},
			{ "PNG ", PT_MSN_IGNORE},
			{ "QNG ", PT_MSN_IGNORE},
			{ "CAL ", PT_MSN_IGNORE},
			{ "BYE ", PT_MSN_BYE},
			{ "CHG ", PT_MSN_CHG},
			{ "ILN ", PT_MSN_ILN},
			{ "SYN ", PT_MSN_SYN},
			{ "GTC ", PT_MSN_IGNORE},
			{ "BLP ", PT_MSN_IGNORE},
			{ "PRP ", PT_MSN_PRP},
			{ "NLN ", PT_MSN_NLN},
			{ "QRY ", PT_MSN_IGNORE},
			{ "LST ", PT_MSN_LST},
			{ "BPR ", PT_MSN_IGNORE},
			{ "CHL ", PT_MSN_IGNORE},
			{ "FLN ", PT_MSN_FLN},
			{ "XFR ", PT_MSN_IGNORE},
			{ "VER ", PT_MSN_IGNORE},
			{ "CVR ", PT_MSN_IGNORE},
			{ NULL, 0}
		};

	for (int i=0; cmds[i].command!=NULL; i++)
	{
           // printf ("\n [%s] [%s] [%d]\n", data, cmds[i].command, strlen (cmds[i].command));
           if (strncmp ((char *) data, cmds[i].command, strlen (cmds[i].command))==0) return cmds[i].type;
	}	
	return PT_UNKNOWN;
}



void process_packet (long packet_id, struct pcap_pkthdr *header, const u_char *packet)
{
        time_t elapsed_mtime;
	struct tm *ltime;
	char timestr[16];

	/* Make sure we have enough data to read the IP header */
	if ( header->caplen < (data_offset + sizeof (struct ip_header)))
		return;

	/* Get IP header, which comes after the datalink header  (14 bytes for ethernet) */
	struct ip_header *ih = (ip_header *) (packet + data_offset);

	/* TCP header comes right after */
    	int ip_len = (ih->ver_ihl & 0xf) * 4;

	struct tcp_header *th = (tcp_header *) ((u_char*)ih + ip_len);

	if ( ( (u_char *) th+sizeof (struct tcp_header)) > (packet + header->caplen) )
	{
		/* the TCP header ends beyond the received data */
		return; 
	}
	
	int source_port = ntohs (th->th_sport);
	int destination_port = ntohs (th->th_dport);

        // Check/change log chat dir after 60 secs
        time_elapsed = time(NULL);
        elapsed_mtime = difftime(time_elapsed, time_start);
        if (elapsed_mtime >= 60) {
           time_start = time_elapsed;
           date_logchat(auxchatlogdir);
        }

        // Unchecked traffic
        // - Consider the use of pcap filter (-filter option)
	if (!use_filter) {
 	  if (proxy_addr != NULL) {
             char ip_src[1024];
             char ip_dst[1024];
	     sprintf(ip_src, "%d.%d.%d.%d:%i",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4, source_port);
	     sprintf(ip_dst, "%d.%d.%d.%d:%i",
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4, destination_port);
	      with_proxy = 1;
	      if ((strcmp(proxy_addr, ip_src) != 0) && (strcmp(proxy_addr, ip_dst) != 0)) return; 
	  }
	  else {
              // this is a default traffic *filter*
              if (source_port!=1863 && destination_port!=1863)
       		return;
	  }
	}
	else with_proxy = 1;

	u_short th_len = (th->off_unused& 0xF0) >> 4;

	// Convert time
	ltime=localtime(&header->ts.tv_sec);
	strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);

        log_debug (5, "Read data on packet");
	u_char *data_onpacket = (u_char *) th +th_len*4;
	int data_onpacket_size = header->caplen - th_len*4 - ip_len - data_offset;
	int comesfromA = 0;
	int data_size;
	u_char *payload; 
	
	int allzeros = 1;
	for (int i=0; i<data_onpacket_size; i++)
	{
        	if (data_onpacket[i]!=0) {
			allzeros=0;
			break;
		}
	}

	if (allzeros)
	{
		log_debug (5, "Ignoring empty or all-zero packet");
		return;
	}

	// Is this packet part of a connection known to be MSN for sure?
	log_debug (5, "Calling: Get or Create MSN connection");
	struct msn_connection *ci = get_or_create_msn_connection (&ih->saddr, source_port, &ih->daddr, 
		destination_port, create_no);
	
	log_debug (3, "Processing packet with ID: %ld", packet_id);
	
	if (ci==NULL)
	{
		log_debug (3, "Packet is not from a known conversation");
		payload=(u_char *) malloc (data_onpacket_size);
		memcpy (payload, data_onpacket, data_onpacket_size);
		data_size=data_onpacket_size;
	}
	else
	{
		if (is_from_A(ci, &ih->saddr, source_port)==1)
		{
			log_debug (3, "Packet is from a known conversation (A), pending =%d", ci->pending_A_length);
			payload=(u_char *) malloc (data_onpacket_size + ci->pending_A_length);
			if (ci->pending_A_length>0)
				memcpy (payload, ci->pending_A, ci->pending_A_length);

			memcpy (payload + ci->pending_A_length, data_onpacket, data_onpacket_size);
			data_size=data_onpacket_size + ci->pending_A_length;
			ci->pending_A_length=0;
	
			if (ci->pending_A!=NULL) free (ci->pending_A);
                        ci->pending_A=NULL;

   			comesfromA=1;
		}
		else
		{
			log_debug (3, "Packet is from a known conversation (B), pending =%d", ci->pending_B_length);
			payload=(u_char *) malloc (data_onpacket_size + ci->pending_B_length);
			if (ci->pending_B_length>0)
				memcpy (payload, ci->pending_B, ci->pending_B_length);

			memcpy (payload + ci->pending_B_length, data_onpacket, data_onpacket_size);
			data_size=data_onpacket_size + ci->pending_B_length;
			ci->pending_B_length=0;

			if (ci->pending_B!=NULL) free (ci->pending_B);			
			ci->pending_B=NULL;

                        comesfromA=0;
		}
	}

	log_debug (3, "Real size = %d, current size=%d",data_onpacket_size, data_size);
	int pos = 0;
	int conn_unknown = 0;
	u_char *ref = payload;
	
        if (data_size < 1) return;

	while (data_size)
	{
		log_debug (5, "In while (data_size)");
		int packet_type;
		if (data_size<3)
		 	packet_type= PT_UNKNOWN;
		else
		 	packet_type = analyze_packet (payload);

		log_debug (5, "data_size = %d, packet type =%d", data_size, packet_type);
		char fromto[1024];
		sprintf(fromto, "%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4, source_port,
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4, destination_port);

		log_debug (3, "%s",fromto);
		log_debug (5, "%s.%.6d longitud:%d (cap: %d)", timestr, header->ts.tv_usec, header->len, header->caplen);

		u_char prefix[1024];
		sprintf ((char *) prefix, "%s | %s | ",timestr, fromto);
		
		// Number of bytes the handler managed
		int bytes_parsed=-1; 

		// Vamos a ver si es un MSG y si tiene buena 
		//  pinta despues
		char line_x[30]="";

		switch (packet_type)
		{
			case PT_UNKNOWN:
				if (ci==NULL)
				{
					log_debug (3, "Unknown data from an unknown conversation, skipping.");
				 	if (!with_proxy) {
					      bytes_parsed = data_size;
					      break;
					}
				}
				else log_debug (3, "Unknown data but from a known MSN conversation, attempting to skip and resume");
				line_x[0]=0;
				for (int j=0; j<data_size; j++)
				{
					sprintf (line_x+strlen (line_x), "%02X ", payload[j]);
					if (j%8==0)
					{
						log_debug (5, "%s",line_x);
						line_x[0] = 0;
					}
				}
				if (strlen (line_x)>0)
					log_debug (5,"%s",line_x);
					
				line_x[0]=0;				
				for (int j=0; j<data_size; j++)
				{
					sprintf (line_x+strlen (line_x), "%c", payload[j]);
					if (j%8==0)
					{
						log_debug (5, "%s",line_x);
						line_x[0]=0;
					}
				}
				if (strlen (line_x)>0)
					log_debug (5,"%s",line_x);

				if (with_proxy) {
				    bytes_parsed = handler_msn_ignore (payload, data_size, ih->saddr, source_port,
				 	 ih->daddr, destination_port);
				}
				else bytes_parsed = get_new_line_malloc (NULL,payload,data_size);
				break;
			case PT_MSN_SYN:
				// List sync.
				conn_unknown = -1;
				bytes_parsed = handler_msn_syn (payload, data_size, ih->saddr, source_port,
					ih->daddr, destination_port);
				break;							
			case PT_MSN_MSG:
				conn_unknown = -1;
				bytes_parsed = handler_msn_msg (payload, data_size, ih->saddr, source_port,
					ih->daddr, destination_port);
				break;							
			case PT_MSN_USR: // User identification and authentification
				conn_unknown = -1;
				bytes_parsed = handler_msn_usr (payload, data_size, ih->saddr, source_port,
					ih->daddr, destination_port);
				break;
			case PT_MSN_ANS: /* Entry in a switchboard after being invited */
				conn_unknown = -1;
				bytes_parsed = handler_msn_ans (payload, data_size, ih->saddr, source_port,
					ih->daddr, destination_port);
				break;
			case PT_MSN_IRO: /* Initial user list in a switchboard */
				conn_unknown = -1;
				bytes_parsed = handler_msn_iro (payload, data_size, ih->saddr, source_port,
					ih->daddr, destination_port);
				break;
			case PT_MSN_JOI: // Usuario entrando en el switchboard
				conn_unknown = -1;
				bytes_parsed = handler_msn_joi (payload, data_size, ih->saddr, source_port,
					ih->daddr, destination_port);					
				break;
			case PT_MSN_OUT: // Session termination
				conn_unknown = -1;
				bytes_parsed = handler_msn_out (payload, data_size, ih->saddr, source_port,
					ih->daddr, destination_port);
				break;
			case PT_MSN_IGNORE: // Ignore these packets
				conn_unknown = -1;
				bytes_parsed = handler_msn_ignore (payload, data_size, ih->saddr, source_port,
					ih->daddr, destination_port);
				break;
			case PT_MSN_BYE: // User leaving switchboard
				conn_unknown = -1;
				bytes_parsed = handler_msn_bye (payload, data_size, ih->saddr, source_port,
					ih->daddr, destination_port);	
				break;
			case PT_MSN_CHG: // User changing status
				conn_unknown = -1;
				bytes_parsed = handler_msn_chg (payload, data_size, ih->saddr, source_port,
					ih->daddr, destination_port);
				break;
			case PT_MSN_ILN: // Initial user status
				conn_unknown = -1;
				bytes_parsed = handler_msn_iln (payload, data_size, ih->saddr, source_port,
					ih->daddr, destination_port);				
				break;
			case PT_MSN_NLN: // User changing status
				conn_unknown = -1;
				bytes_parsed = handler_msn_nln (payload, data_size, ih->saddr, source_port,
					ih->daddr, destination_port);							
				break;
			case PT_MSN_LST: // Contact list
				conn_unknown = -1;
				bytes_parsed = handler_msn_lst (payload, data_size, ih->saddr, source_port,
					ih->daddr, destination_port);		
				break;
			case PT_MSN_PRP: // Contact list
				conn_unknown = -1;
				bytes_parsed = handler_msn_prp (payload, data_size, ih->saddr, source_port,
					ih->daddr, destination_port);	
				break;
			case PT_MSN_FLN: // Contact list
				conn_unknown = -1;
				bytes_parsed = handler_msn_fln (payload, data_size, ih->saddr, source_port,
					ih->daddr, destination_port);				
				break;
			default:
				log_debug (0, "this is a bug! (packet_Type=%d)", packet_type);
				bytes_parsed = data_size; /* Don't know what it is, skip the whole thing */
				break;

		}

		switch (bytes_parsed)
		{
			case NOT_MSN:
				if (with_proxy && conn_unknown <= 12 && conn_unknown >= 0) {
					conn_unknown++;
				        data_size -=bytes_parsed;
 				        payload += bytes_parsed;	
				        log_debug (3, "Skipping the current line");
				}
				else {
				   bytes_parsed = data_size; /* Don't know what it is, skip the whole thing */
				   data_size = 0;
				   log_debug (3, "Skipping rest of packet");
				}
				break;
			case LINE_INCOMPLETE:
				log_debug (3, "Processed = LINE_INCOMPLETE, no complete line available");
				if (ci!=NULL) /* It's from a known conversation, store the rest of stuff for later */
				{
					if (comesfromA)
					{
						log_debug (3, "It's from a known conversation (A > B), added to pending data");
						if (ci->pending_A!=NULL)
							log_debug (0, "pending_A has data!");
						ci->pending_A=(u_char *) malloc (data_size);
						memcpy (ci->pending_A,payload,data_size);
						ci->pending_A_length=data_size;
					}
					else
					{
						log_debug (3, "It's from a known conversation (B > A), added to pending data");
						if (ci->pending_B!=NULL)
							log_debug (0, "pending_B has data!");
						
						ci->pending_B=(u_char *) malloc (data_size);
						memcpy (ci->pending_B,payload,data_size);
						ci->pending_B_length=data_size;
					}
					if (ci->pending_A_length>8192 || ci->pending_B_length>8192)
					{
						/* No payload is this long - skip everything */
						log_debug (3, "Payload too long, skipping everything");
						remove_msn_connection(ci);
					}				
				}
				bytes_parsed = data_size; /* Get out */
				data_size = 0;
				break;
			case CONN_DESTROYED:
				bytes_parsed = data_size; /* Pointless to go on... */
				data_size = 0;
				break;
			case OUT_OF_MEMORY:
				log_debug (0, "Out of memory somewhere, likely to crash soon");				
				bytes_parsed = data_size; /* Get out */
				data_size = 0;
				break;
			default:
				data_size -=bytes_parsed;
				payload += bytes_parsed;	
		}
	}
	log_debug (5, "Freeing stuff");
	/* if (dump!=NULL)
		free (dump); */

	if (ref!=NULL) free (ref);
	log_debug (5, "Leaving process_packet");	
}

int go_daemon (void)
{
        pid_t pid, sid;
        
        /* Fork off the parent process */
        pid = fork();
        if (pid < 0) 
		return -1;	
	
	if (pid>0)        
	   return 1;

        /* Change the file mode mask */
        umask(0);       
        
        /* Create a new SID for the child process */
        sid = setsid();
        if (sid < 0) 
	{
		return -1;
        }
        
        /* Change the current working directory */
        if ((chdir("/")) < 0) {
		return -1;
        }
        
        /* Close out the standard file descriptors */
        close(STDIN_FILENO);
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
	return 0;        
}

int process_parms (int argc, char *argv[])
{
	int i=1, j=0;
	while (i<argc)
	{
		if (strcmp (argv[i], "-help")==0 || strchr (argv[i],'?'))
		{
			show_help ();
			exit (-1);
		}

		if (strcmp (argv[i], "-filter")==0)
		{
		    int countf = 0;
	            strcat(filter_app, " and (");
	            for (j = i + 1; j < argc && argv[j][0] != '-'; j++) {
	                strcat(filter_app, " ");
	                strcat(filter_app, argv[j]);
			countf++;
                        i++;
	            }
	            strcat(filter_app, " )");
	            if (countf < 1) {
	               printf("Incomplete filter: %s \n\n", filter_app);
	               return -1;
	            }

		    use_filter = 1;
		}
		if (strcmp (argv[i], "-proxy")==0)
		{
			if (i==argc-1)
			{
				printf ("-proxy requires a parameter.\n");
				return -1;
			}
			strcpy (proxy_addr,argv[i+1]);
			i++;
		}
		else
		if (strcmp (argv[i], "-cd")==0)
		{
			if (i==argc-1)
			{
				printf ("-cd requires a parameter.\n");
				return -1;
			}
   
                        // Include date informations into chatlogdir
			strcpy (auxchatlogdir,argv[i+1]);
			strcpy (debuglogdir,argv[i+1]);
			strcat (debuglogdir,"/debug");
                        date_logchat(auxchatlogdir);
			i++;
		}
		else
		if (strcmp (argv[i], "-d")==0)
		{
			daemonize=1;
		}
		else
		if (strcmp (argv[i], "-p")==0)
		{
			promisc=1;
		}
		else
		if (strncmp (argv[i],"-v",2)==0)
		{
			int v=0;
			for (char *c=argv[i];*c;c++)
				if (*c=='v')
					v++;
			debug_level=v;
		}
		else
		if (strcmp (argv[i], "-offset")==0)
		{
			if (i==argc-1)
			{
				printf ("-offset requires a parameter.\n");
				return -1;
			}
			data_offset=atoi (argv[i+1]);
			i++;			
		}
		else
		if (strcmp (argv[i], "-i")==0)
		{
			strcpymalloc((u_char **) &devname, (u_char *) argv[i+1]);
			i++;
		}
		i++;		
	}
	return 0;
}

void show_help (void)
{
		printf ("\nimsniffer %s, by betolj@gmail.com\n", currentversion);
		printf ("http://humbertolj.sourceforge.net/\n");
		printf ("imsniffer is a fork of  http://im-snif.sourceforge.net\n");
		printf ("Released under GPL v2\n");
		printf ("-----------------------------------------------\n");
		printf ("Usage:\n\n");
		printf ("imsnif [-cd chat_dir] [-p] -[d] -[vvv...] [-proxy server:port] [-filter pcap] -i interface\n\n");
		printf ("where:\n\n");
		printf ("Server options\n");
		printf ("	chat_dir  -> directory where chat logs, event logs\n");
		printf ("	             and contact lists will be stored. If\n");
		printf ("	             not specified, output will go to stdout\n");
		printf ("	-d        -> Daemonize, i.e. make imsniffer put itself\n");
		printf ("	             in the background.\n");
		printf ("	-vvv      -> Debug mode. The more 'v' you use, the more\n");
		printf ("	             verbose output will be\n");
		printf ("	-offset   -> Offset from packet start to data start, in case\n");
		printf ("	             you are using a datalink layer imsniffer does not\n");
		printf ("	             know about\n\n");

		printf ("Traffic options... default traffic is only tcp/1863 (main pcap)\n");
		printf ("	-p        -> Use promiscuous mode. Whether you need it\n");
		printf ("	             or not depends on your setup.\n");
		printf ("	-filter   -> Pcap filter (change the main pcap filter).\n");
		printf ("	-proxy    -> Analyse only <proxy>:<port>.\n\n");

		printf ("Sniffed interface\n");
		printf ("	-i        -> Device name (such as eth0) to listen to.\n\n");
}

void read_file (FILE *f)
{
	long length;
	fseek (f, 0, SEEK_END);
	length = ftell (f);
	fseek (f, 0, SEEK_SET);	
	char *data = (char *) malloc (length + 1);
	fread (data, 1, length, f);
	fclose (f);
	data[length]=0;
	char *c = data;
	int line = 1;
        int param = 1;
	while (c< (data + length))
	{
		while (*c && (*c=='\n' || *c=='\r'))
			c++;
		if (!*c)
			break;
		char *d = strchr (c, '\n');
		if (d == NULL)
			d= strchr (c, '\r');
		if (d != NULL)
			*d = 0;
		char *next = c+strlen (c)+1;
		d = strchr (c, '#');
		if (d != NULL)
			*d = 0;
		d= strchr (c, '=');
		if (d != NULL)
			*d = ' ';
		if (get_tokens((u_char*) c,  &line_tokens, 0)==2)
		{
			log_debug (0, "Parsing %s", c);
			u_char *s = line_tokens[0];
			while (*s)
			{
				*s=tolower (*s);
				s++;
			}
			if (strcmp ((char *) line_tokens[0], "chatdir")==0)
			{
       		                 // Include date informations into chatlogdir
				strncpy (auxchatlogdir, (char *) line_tokens[1], MAX_DIR_LENGTH);
				strncpy (debuglogdir, (char *) line_tokens[1], MAX_DIR_LENGTH);
				auxchatlogdir[MAX_DIR_LENGTH]=0;
				debuglogdir[MAX_DIR_LENGTH]=0;
                                date_logchat(auxchatlogdir);
			        strcpy (debuglogdir,auxchatlogdir);
			        strcat (debuglogdir,"/debug");
             
				log_debug (0, "chatdir = %s", chatlogdir);
			}

			if (strcmp ((char *) line_tokens[0], "daemonize")==0)
			{
				daemonize=atoi ((char *) line_tokens[1]);
				log_debug (0, "daemonize = %d", daemonize);
			}

			if (strncmp ((char *) line_tokens[0], "promisc", 7)==0)
			{
				promisc=atoi ((char *) line_tokens[1]);
				log_debug (0, "promisc = %d", daemonize);
			}
			if (strcmp ((char *) line_tokens[0], "verbose")==0)
			{
				debug_level=atoi ((char *) line_tokens[1]);
				log_debug (0, "verbose = %d", debug_level);
			}			
			if (strcmp ((char *) line_tokens[0], "data_offset")==0)
			{
				data_offset=atoi ((char *) line_tokens[1]);
				log_debug (0, "data_offset = %d", data_offset);
			}
			if (strcmp ((char *) line_tokens[0], "interface")==0)
			{
				strcpymalloc((u_char **) &devname, line_tokens[1]);
				log_debug (0, "interface = %s", devname);
			}
			if (strcmp ((char *) line_tokens[0], "proxy")==0)
			{
			        strcpy (proxy_addr,(const char *) line_tokens[1]);
				log_debug (0, "Proxy address = %s", proxy_addr);
			}
			if (strcmp ((char *) line_tokens[0], "filter")==0)
			{
		            strcat(filter_app, " and (");
                            while(line_tokens[param]) {
			         strcat(filter_app, " ");
			         strcat(filter_app, (const char *) line_tokens[param]);

 				 param++;
                            }
	 	            strcat(filter_app, " )");
		            use_filter = 1;

 			    if (param < 3) printf("Incomplete filter: %s \n\n", filter_app);
			    log_debug (0, "Pcap filter = %s", filter_app);
			}
		}
		else
		{
			log_debug (0, "Skipping %s", c);
		}
		c=next;
		line++;
	}
	free (data);
}

int parse_config (char *myname)
{
	char *c = myname + strlen (myname);
	char *fn;
	FILE *f;
	while (c>=myname && *c!='/' && *c!='\\')
		c--;
	c++; /* Start of real name */
	if (strlen (c) == 0) /* Uh? */
		return 0;
	if (strchr (c, '%')!=NULL) /* Prevent strange things */
		return -1;
	fn = (char *) malloc (strlen (c) + 11);
	if (fn == NULL)
		return -1;
	sprintf (fn, "/etc/%s.conf", c);
	f= fopen (fn, "r");
	if (f == NULL)
	{
		sprintf (fn, "%s.conf", c);
		f = fopen (fn, "r");
	}
	if (f!=NULL)
	{
		read_file (f);
	}
	free (fn);
	return 0;
}

int main (int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *dh;
 	struct bpf_program filter;               
    	bpf_u_int32 mask;                      
    	bpf_u_int32 net;                       
	struct pcap_pkthdr header;         
        const u_char *packet;      
	
	if (parse_config (argv[0]))
	{
		printf ("Failed to parse config file, leaving\n");
		return -1;
	}

	if (process_parms (argc,argv))
	{
		printf ("Bad parameters, leaving\n");
		return -1;
	}

	if (devname==NULL)	
	{
		printf ("A device name (such as eth0) is required\n");
		exit (-1);
	}

	if (daemonize)
	{
		switch (go_daemon())
		{
			case -1:
				daemonize=0;			
				log_debug (0, "Failed to become a daemon!");
				exit (-1);
			case 1:
				// We are the parent. Exit and let the child on its own
				exit (0);
			case 0:
				log_debug (3, "Successfully became a daemon.");
				break;
			default:
				daemonize=0;
				log_debug (0, "This is a bug!");
				exit (-1);
		}
	}
	else strcpy (debuglogdir,"");

	log_debug (3, "Getting address and mask for device %s...",devname);
    	if (pcap_lookupnet(devname, &net, &mask, errbuf)==-1)
	{
		log_debug (0, "error [%s]",errbuf);
		exit (-1);
	}
	log_debug (3, "OK");

	log_debug (3, "Opening device...");
	dh = pcap_open_live (devname, 65535, promisc, 1000, errbuf);

	if (dh==NULL)
	{
		log_debug (0, "error [%s]",errbuf);
		exit (-1);
	}

	log_debug (3, "OK");
	if (data_offset == -1) /* User didn't force an offset, try to find out */
	{
		char *dln;
		log_debug (3, "Checking datalink type...");
		if (get_datalink_info (dh, &dln, &data_offset))
		{
			log_debug (0, "not supported. Please play with the -offset option (see docs)");
			exit (-1);
		} 
		log_debug (3, "OK, %s, offset = %d", dln, data_offset);
	}
	else
	{
		log_debug (1, "Using an user defined offset [%d], for datalink type [%d], good luck!", 
			data_offset, get_datalink_type(dh));
	}
	log_debug (3, "Compiling filter [%s]...",filter_app);
  	if (pcap_compile(dh, &filter, filter_app, 0, net)==-1)
	{
		log_debug (0, "error: Couldn't parse filter %s", filter_app);
		exit (-1);
	}
	log_debug (3, "OK");
	log_debug (3, "Setting filter...");
	if (pcap_setfilter(dh, &filter)==-1)
	{
		log_debug (0, "error [%s]",errbuf);
		exit (-1);
	}
	log_debug (3, "OK");
	log_debug (3, "Entering capture loop...");

	if (chatlogdir[0]!=0) mkdir (chatlogdir,0700);
	if (debuglogdir[0]!=0) mkdir (debuglogdir,0700);
	long packet_count = 0;
		
	while (1)
	{
		packet = pcap_next(dh, &header);
		if (packet==NULL)
		{
			log_debug (5, "No packet received");
			continue;
		}
		process_packet (++packet_count, &header,packet);
	}
}

