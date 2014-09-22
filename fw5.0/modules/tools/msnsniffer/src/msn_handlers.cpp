
/* MSN Handlers 
---------------
These functions always take the same parameters:

u_char *raw -> Start of data to analyze
int length -> Length of data
ip_address source -> Packet's source IP address
u_short source_port -> Packet's source port
ip_address target -> Packet's target IP address
u_short target_port -> Packet's target port

And they must always return:

LINE_INCOMPLETE if the data is incomplete (most likely it continues in the next packet)
OUT_OF_MEMORY 
NOT_MSN if there was en error parsing the data which makes it likely that it's not MSN

otherwise, the number of bytes processed, so the main packet process loop knows where to 
continue 
*/

#include "msnsniffer.h"

static u_char *next_line=NULL; // Functions can use this to get the next line
u_char **line_tokens=NULL; //  Split tokens go here

int handler_msn_ignore (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port)
{
	return get_new_line_malloc (&next_line, raw, length);

}

int handler_msn_msg (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port)
{
	int rc, nt;
	u_char *typingnick = NULL;
	log_debug (4, "Entry into handler_msn_msg");
	rc= get_new_line_malloc (&next_line, raw, length);
	if (rc<0)
		return rc;
	nt= get_tokens (next_line, &line_tokens, 0); /* Split in all tokens */
	if (nt!=4)
		return NOT_MSN;
	int pl = atoi ((char *) line_tokens[3]);
	log_debug (5, "Payload length: %d", pl);
	if (pl > length-rc) /* We don't have the whole payload yet */
		return LINE_INCOMPLETE;
	struct msn_connection *conn = get_or_create_msn_connection
	 	(&source,source_port,&destination,destination_port,
		create_yes);
		
	int rem = pl;		
	u_char *payload_start = raw+rc;
	u_char *now =payload_start;
	u_char **header_tk=NULL;
	u_char *newemailfrom=NULL, *newemailsubj=NULL, *newemailaddr=NULL; 
	int header=1;
	rc=pl + rc; // Payload + MSG line
	int block_type = BT_UNKNOWN;

	while (rem>0)
	{
		int j= get_new_line_malloc (&next_line, now, rem);
		
		if (j==LINE_INCOMPLETE) // Payload doesn't have  have to end in \r\n
		{
			memcpy (next_line,now,rem);
			j= rem;
		}
		if (j==OUT_OF_MEMORY)
		{
			rc = OUT_OF_MEMORY;
			break;
		}
		log_debug (5, " MSG : %d : [%s]", header, next_line);
		if (header)
		{
			if (j==2)
				header=0;
			else
			if (get_tokens(next_line,&header_tk,2)==2)
			{
				log_debug (5, "Word: %s | %s", header_tk[0], header_tk[1]);
				if (strcasecmp ((char *) header_tk[0],"Content-Type:")==0)
				{
					log_debug (5, "Its a content-type");
					if (!strncmp ((char *) header_tk[1], "text/plain", 
						strlen ("text/plain")))
					{
						log_debug (5, "text/plain");
						block_type = BT_TEXTPLAIN;
					}
					else
					if (strstr ((const char *) 
						header_tk[1], "x-msmsgscontrol")) 
					{
						block_type = BT_CONTROL;
						log_debug (5, "Control");
					}
					else
					if (strstr ((const char *) 
						header_tk[1], "text/x-msmsgsprofile")) 
					{
						block_type = BT_PROFILE;
						delete_profile (conn->owner);
						log_debug (5, "Profile");
						log_profile(conn->owner, payload_start, pl);
						break;
					}
					else
					if (strstr ((const char *) 
						header_tk[1], "text/x-msmsgsinitialemailnotification")) 
					{
						block_type = BT_INITIAL_EMAIL;
						log_debug (5, "Initial mail notification");
					}
					else
					if (strstr ((const char *) 
						header_tk[1], "text/x-msmsgsemailnotification")) 
					{
						block_type = BT_NEW_EMAIL;
						log_debug (1, "New mail notification");
					}
					else
					{
						log_debug (1, "Unknown content-type: %s", header_tk[1]);
					}
				}
				if (strcasecmp ((char *) header_tk[0],"TypingUser:")==0)
				{
					log_debug (5, "It's a typing user!: %s", header_tk[1]);
					if (conn->owner==NULL)
					{
						conn->conn_type=type_switchboard;
						log_debug (5, "Unknown owner");
						if (strchr ((char *)
						 	line_tokens[1],'@')!=NULL)
						{
							log_debug (5, "Incoming: %s",line_tokens[1]);
							typingnick=line_tokens[1];
						}
						else
						{
							log_debug (5, "Outgoing?: %s",
							header_tk[1]);
							set_owner(conn,header_tk[1]);
							typingnick=conn->owner;
						}
					}
					else
					{
						log_debug (5, "SB owner: %s", 
							conn->owner);
					}
				}		
			}
		}
		else
		{
			switch (block_type)
			{
				case BT_TEXTPLAIN:
					if (strchr ((char *) line_tokens[1],'@')!=NULL)
					{
						typingnick=line_tokens[1];
						add_user_to_sb(conn,typingnick);
					}
					else
						typingnick=(conn->owner==NULL) ? (u_char *) "Unknown" : conn->owner;
					log_switchboard_event(conn, "%s: %s", typingnick, next_line);
					break;
				case BT_PROFILE:
					log_debug (0, "Profile with a body? Shouldn't happen");
					break;
				case BT_INITIAL_EMAIL:
					if (get_tokens(next_line,&header_tk,2)==2)
					{
						if (strcmp ((char *) header_tk[0],"Inbox-Unread:")==0)
							log_event(conn->owner, "has %s unread emails in his/her inbox",
								header_tk[1]);
						if (strcmp ((char *) header_tk[0],"Folders-Unread:")==0)
							log_event(conn->owner, "has %s unread emails in other folders",
								header_tk[1]);		
					}
					break;
				case BT_NEW_EMAIL:
					if (get_tokens(next_line,&header_tk,2)==2)
					{
						if (strcmp ((char *) header_tk[0],"From:")==0)
							strcpymalloc(&newemailfrom, header_tk[1]);
						if (strcmp ((char *) header_tk[0],"Subject:")==0)
							strcpymalloc(&newemailsubj, header_tk[1]);
						if (strcmp ((char *) header_tk[0],"From-Addr:")==0)
							strcpymalloc(&newemailaddr, header_tk[1]);
					}
					break;
				default:
					log_debug (5, "%d - %s:%s", block_type, line_tokens[1], line_tokens[2]);
					// dump_tokens(line_tokens);			
					break;
			}
		}
		now=now+j;
		rem=rem-j;
	}
	if (block_type==BT_NEW_EMAIL)
	{
		log_event(conn->owner, "got email from [%s] (%s) about [%s]",
			(u_char *) newemailfrom ? (u_char *) newemailfrom : (u_char *) "Unknown",
			(u_char *) newemailaddr ? (u_char *) newemailaddr : (u_char *) "unknown address",
			(u_char *) newemailsubj ? (u_char *) newemailsubj : (u_char *) "(no subject)");
	}
	free_array (&header_tk);
	free (newemailfrom);
	free (newemailsubj);
	free (newemailaddr);
	return rc;
}

/* USR
   When user -> server, attempt to identify 
   When server -> user, request to authentificate or final OK 
   Useful information here: Connection owner's ID
   */
   
int handler_msn_usr (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port)
{
	int rc, nt;
	log_debug (4, "Entry into handler_msn_usr");
	rc= get_new_line_malloc (&next_line, raw, length);
	if (rc<0)
		return rc;
	nt= get_tokens (next_line, &line_tokens, 0); /* Split in all tokens */
	if (nt == 5)
	{
		
		if (strcmp ((char *) line_tokens[2], "TWN")==0 || strcmp ((char *) line_tokens[2], "SSO")==0) 
		{
			if (strcmp ((char *) line_tokens[3],"I")==0)
			{
				log_event (line_tokens[4],"trying to log in");
				struct msn_connection *conn = get_or_create_msn_connection (&source,source_port,&destination,destination_port,
					create_yes);
				set_owner (conn, line_tokens[4]);
				conn->conn_type=type_notification_server;
				set_as_server(conn,&destination,destination_port);
			}
			if (strcmp ((char *) line_tokens[3], "S")==0)
			{
				/* We only process this for notification purposes, but it's not really useful 
				   since there's no information we need here */
				struct msn_connection *conn = get_or_create_msn_connection (&source,source_port,&destination,destination_port,
					create_no);
				u_char *nick=NULL;
				if (conn!=NULL)
				{
					nick=conn->owner;
					conn->conn_type=type_notification_server;
				}
				log_event (nick, "Notification server authentificating user");
			}
			
		}
		if (strcmp ((char *) line_tokens[2], "OK")==0) 
		{
			// User successfully logged into a SB
				struct msn_connection *conn = get_or_create_msn_connection (&source,source_port,&destination,destination_port,
					create_yes);
				set_owner (conn, line_tokens[3]);
				conn->conn_type=type_notification_server;
				set_as_server(conn,&source,source_port);			
				log_event (line_tokens[3], "entered switchboard at %d.%d.%d.%d:%d",
					source.byte1,source.byte2,source.byte3,source.byte4,
					source_port);
		}
	}
	else if (nt == 4)
	{
		log_event (line_tokens[2],"attempting to enter switchboard at %d.%d.%d.%d:%d",
			destination.byte1,destination.byte2,destination.byte3,destination.byte4,
			destination_port);
	}
	else if (nt == 6 || nt == 7) /* No idea why sometimes it's 7 */
	{
		if (strcmp ((char *) line_tokens[2], "OK")==0)
		{
			log_event (line_tokens[3],"successfully authentificated");
			struct msn_connection *conn = get_or_create_msn_connection (&source,source_port,&destination,destination_port,
				create_yes);
			set_owner (conn, line_tokens[3]);
			conn->conn_type=type_notification_server;
			set_as_server(conn,&source,source_port);
			
		}

	}
	else
	{
		log_debug (0, "Unable to parse USR correcty");
		log_debug (0, "Line read: %s", next_line);
	        dump_tokens (line_tokens);	
	        return NOT_MSN;
	}
	return rc;	
}

/* CHG - change status information */
int handler_msn_chg (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port)
{
	int rc, nt;
	log_debug (4, "Entry into handler_msn_chg");
	rc= get_new_line_malloc (&next_line, raw, length);
	if (rc<0)
		return rc;
	nt= get_tokens (next_line, &line_tokens, 0); /* Split in all tokens */
	if (nt >= 4)
	{
		struct msn_connection *conn = get_or_create_msn_connection
			(&source,source_port,&destination,destination_port,
			create_no);
		u_char *nick=NULL;
		if (conn!=NULL)
			nick=conn->owner;
		log_event (nick, "Changed status to %s", line_tokens[2]);
	
	}
	else
	{
		log_debug (0, "Unable to parse CHG correcty");
		log_debug (0, "Line read: %s", next_line);
	        dump_tokens (line_tokens);	
	        return NOT_MSN;
	}
	return rc;
}

/* ANS - join a switchboard we have been invited to */
int handler_msn_ans (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port)
{
	int rc, nt;
	log_debug (4, "Entry into handler_msn_ans");
	rc= get_new_line_malloc (&next_line, raw, length);
	if (rc<0)
		return rc;
	nt= get_tokens (next_line, &line_tokens, 0); /* Split in all tokens */
	if (nt == 5)
	{
		struct msn_connection *conn = get_or_create_msn_connection
			(&source,source_port,&destination,destination_port,
			create_yes);
		set_owner(conn, line_tokens[2]);
		log_event (line_tokens[2], "is entering the SB at %d.%d.%d.%d:%d", 
			destination.byte1,destination.byte2,destination.byte3,
			destination.byte4,destination_port);
		set_as_server(conn,&destination,destination_port);
	
	}
	else 
	if (nt == 3 && strcmp ((char *) line_tokens[2], "OK")==0)
	{
		struct msn_connection *conn = get_or_create_msn_connection
			(&source,source_port,&destination,destination_port,
			create_no);
		u_char *nick=NULL;
		if (conn!=NULL)
			nick=conn->owner;	
		log_event (nick, "successfully logged into SB at %d.%d.%d.%d:%d", 
			source.byte1,source.byte2,source.byte3,
			source.byte4,source_port);
		set_as_server(conn,&source,source_port);
	}
	else
	{	
		log_debug (0, "Unable to parse ANS correcty");
		log_debug (0, "Line read: %s", next_line);
		dump_tokens (line_tokens);	
		return NOT_MSN;
	}
	return rc;
}

/* IRO - initial list of people in a switchboard */
int handler_msn_iro (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port)
{
	int rc, nt;
	log_debug (4, "Entry into handler_msn_iro");
	rc= get_new_line_malloc (&next_line, raw, length);
	if (rc<0)
		return rc;
	nt= get_tokens (next_line, &line_tokens, 0); /* Split in all tokens */
	if (nt == 6)
	{
		struct msn_connection *conn = get_or_create_msn_connection
			(&source,source_port,&destination,destination_port,
			create_no);
		u_char *nick=NULL;
		if (conn!=NULL)
			nick=conn->owner;		
		urldecode (line_tokens[5]);
		log_event (nick, "%s (%s) is in the SB at %d.%d.%d.%d:%d", 
			line_tokens[4], line_tokens[5], source.byte1,source.byte2,source.byte3,
			source.byte4,source_port);
		set_as_server(conn,&source,source_port);
		add_user_to_sb (conn,line_tokens[4]);
		log_switchboard_event(conn, "%s (%s) is in the conversation", line_tokens[4],
			line_tokens[5]);
	}
	else
	{
	
		log_debug (0, "Unable to parse IRO correcty");
		log_debug (0, "Line read: %s", next_line);
		dump_tokens (line_tokens);	
		return NOT_MSN;
	}
	return rc;
}

/* JOI - new participants entering a switchboard */
int handler_msn_joi (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port)
{
	int rc, nt;
	log_debug (4, "Entry into handler_msn_joi");
	rc= get_new_line_malloc (&next_line, raw, length);
	if (rc<0)
		return rc;
	log_debug (5, "Line read: %s", next_line);
	nt= get_tokens (next_line, &line_tokens, 0); /* Split in all tokens */
	if (nt == 3 || nt == 4)
	{
		struct msn_connection *conn = get_or_create_msn_connection
			(&source,source_port,&destination,destination_port,
			create_no);
		u_char *nick=NULL;
		if (conn!=NULL)
			nick=conn->owner;

		set_as_server(conn,&source,source_port);
		if (line_tokens[1]) {
  	           log_debug (5, "Add user to sb JOI %s", line_tokens[1]);
                   add_user_to_sb (conn,line_tokens[1]);
	   	   urldecode (line_tokens[2]);
                }	
		log_switchboard_event(conn, "%s (%s) joined the conversation", line_tokens[1], line_tokens[2]);
	}
	else
	{
		log_debug (0, "Unable to parse JOI correcty");
     	        dump_tokens (line_tokens);	
	        return NOT_MSN;
	}
	log_debug (5, "Return rc JOI");
	return rc;
}

/* OUT - user leaving the switchboard */
int handler_msn_out (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port)
{
	int rc, nt;
	log_debug (4, "Entry into handler_msn_out");
	rc= get_new_line_malloc (&next_line, raw, length);
	if (rc<0)
		return rc;
	log_debug (5, "Line read: %s", next_line);
	nt= get_tokens (next_line, &line_tokens, 0); /* Split in all tokens */
	if (nt==1 || nt==2) // 2 because trillian add's a TrID
	{
		struct msn_connection *conn = get_or_create_msn_connection
			(&source,source_port,&destination,destination_port,
			create_no);
		u_char *nick=NULL;
		if (conn!=NULL)
			nick=conn->owner;		
		log_event (nick, "is leaving the SB at %d.%d.%d.%d:%d", 
			destination.byte1,destination.byte2,destination.byte3,
			destination.byte4,destination_port);
		log_switchboard_event(conn, "%s left the conversation", nick);
		log_switchboard_end (conn);
		remove_msn_connection (conn);
		return CONN_DESTROYED;
	}
	else
	{
		log_debug (0, "Unable to parse OUT correcty");
		dump_tokens (line_tokens);	
		return NOT_MSN;
	}
	return rc;
}


/* BYE - user has the switchboard or it has been closed for idleness */
int handler_msn_bye (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port)
{
	int rc, nt;
	log_debug (4, "Entry into handler_msn_bye");
	rc= get_new_line_malloc (&next_line, raw, length);
	if (rc<0)
		return rc;
	log_debug (5, "Line read: %s", next_line);
	nt= get_tokens (next_line, &line_tokens, 0); /* Split in all tokens */
	if (nt==2) 
	{
		struct msn_connection *conn = get_or_create_msn_connection
			(&source,source_port,&destination,destination_port,
			create_no);
		u_char *nick=NULL;
		if (conn!=NULL)
		{
			nick=conn->owner;		
			set_as_server(conn,&source,source_port);
		}
		log_switchboard_event (conn, "%s left the conversation", line_tokens[1]);
		// TODO: Remove user from the SB structure
	}
	else
	if (nt==3)
	{
		struct msn_connection *conn = get_or_create_msn_connection
			(&source,source_port,&destination,destination_port,
			create_no);
		u_char *nick=NULL;
		if (conn!=NULL)
			nick=conn->owner;		
		log_switchboard_event (conn, "The switchboard is being closed for idleness");
		log_switchboard_end (conn);
		remove_msn_connection (conn);
		return CONN_DESTROYED;		
	}
	else 
	{
		log_debug (0, "Unable to parse BYE correcty");
		dump_tokens (line_tokens);	
		return NOT_MSN;
	}
	return rc;
}

/* FLN - user disconnecting or hidding */
int handler_msn_fln (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port)
{
	int rc, nt;
	log_debug (4, "Entry into handler_msn_fln");
	rc= get_new_line_malloc (&next_line, raw, length);
	if (rc<0)
		return rc;
	nt= get_tokens (next_line, &line_tokens, 0); /* Split in all tokens */
	if (nt==2) 
	{
		struct msn_connection *conn = get_or_create_msn_connection
			(&source,source_port,&destination,destination_port,
			create_no);
		u_char *nick=NULL;
		if (conn!=NULL)
			nick=conn->owner;		
		log_event (nick, "%s disconnected or hid", 
			line_tokens[1],
			destination.byte1,destination.byte2,destination.byte3,
			destination.byte4,destination_port);
	}
	else
	{
		log_debug (0, "Unable to parse FLN correcty");
		log_debug (0, "Line read: %s", next_line);
		dump_tokens (line_tokens);	
		return NOT_MSN;
	}
	return rc;
}

/* NLN - status change */
int handler_msn_nln (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port)
{
	int rc, nt;
	log_debug (4, "Entry into handler_msn_nln");
	rc= get_new_line_malloc (&next_line, raw, length);
	if (rc<0)
		return rc;
	nt= get_tokens (next_line, &line_tokens, 0); /* Split in all tokens */
	if (nt>=5) 
	{
		struct msn_connection *conn = get_or_create_msn_connection
			(&source,source_port,&destination,destination_port,
			create_no);
		u_char *nick=NULL;
		if (conn!=NULL)
			nick=conn->owner;
		urldecode (line_tokens[3]);
		log_event (nick, "%s [%s] changed his/her status to %s", 
			line_tokens[2],line_tokens[3],line_tokens[1]);
	}
	else
	{
		log_debug (0, "Unable to parse NLN correcty");
		log_debug (0, "Line read: %s", next_line);
		dump_tokens (line_tokens);	
		return NOT_MSN;
	}
	return rc;
}

/* ILN - initial user user */
int handler_msn_iln (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port)
{
	int rc, nt;
	log_debug (4, "Entry into handler_msn_iln");
	rc= get_new_line_malloc (&next_line, raw, length);
	if (rc<0)
		return rc;
	nt= get_tokens (next_line, &line_tokens, 0); /* Split in all tokens */
	if (nt>=6) 
	{
		struct msn_connection *conn = get_or_create_msn_connection
			(&source,source_port,&destination,destination_port,
			create_no);
		u_char *nick=NULL;
		if (conn!=NULL)
			nick=conn->owner;
		urldecode (line_tokens[4]);			
		log_event (nick, "Contact status, nick [%s], status [%s], display name [%s]", line_tokens[3], 
		line_tokens[2],line_tokens[4]);
	}
	else
	{
		log_debug (0, "Unable to parse ILN correcty");
		log_debug (0, "Line read: %s", next_line);
		dump_tokens (line_tokens);	
		return NOT_MSN;
	}
	return rc;
}

/* SYN - list sync */
int handler_msn_syn (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port)
{
	int rc, nt;
	log_debug (5, "Entry into handler_msn_syn");
	rc= get_new_line_malloc (&next_line, raw, length);
	if (rc<0)
		return rc;
	nt= get_tokens (next_line, &line_tokens, 0); /* Split in all tokens */
	struct msn_connection *conn = get_or_create_msn_connection
		(&source,source_port,&destination,destination_port,
		create_no);
	u_char *nick=NULL;
	if (conn!=NULL)
		nick=conn->owner;
	
	switch (nt)
	{
		case 3:
		case 4: /* Trillian sends something else */
			if (conn!=NULL)
			{
				switch (is_from_server(conn,&source,source_port))
				{
					case 1:
						log_event (nick, "has an updated contact list");
						break;
					case 0:
						log_event (nick, "requested a list sync");
						break;
					default:
						log_debug (0, "bug in handler_msn_syn");
						break;
				}
			}
			else
			{
				log_debug (0, "Saw a SYN, can't tell origin");
			}
			break;
		case 6:
			log_event (nick, "has an outdated contact list, a new one should follow");
			log_event (nick, "# of contacts = %s, # of groups= %s", line_tokens[4], line_tokens[5]);
			delete_contact_list (nick);
			break;
		default:
			log_debug (0, "Unable to parse SYN correcty");
			log_debug (0, "Line read: %s", next_line);
   	         	dump_tokens (line_tokens);	
          		return NOT_MSN;
	}
	return rc;
}

/* PRP - list of contacts */
int handler_msn_prp (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port)
{
	int rc, nt;
	log_debug (4, "Entry into handler_msn_prp");
	rc= get_new_line_malloc (&next_line, raw, length);
	if (rc<0)
		return rc;
	nt= get_tokens (next_line, &line_tokens, 0); /* Split in all tokens */
	if (nt==3)
	{
		if (strcmp ((char *) line_tokens[1],"MFN")==0)
		{
			struct msn_connection *conn = get_or_create_msn_connection
				(&source,source_port,&destination,destination_port,
				create_no);
			u_char *nick=NULL;
			if (conn!=NULL)
				nick=conn->owner;		
			urldecode (line_tokens[2]);
			log_event(nick, "Changed display name to [%s]", line_tokens[2]);
		}	
	}
	else
	if (nt==4)
	{
		if (strcmp ((char *) line_tokens[2],"MFN")==0)
		{
			struct msn_connection *conn = get_or_create_msn_connection
				(&source,source_port,&destination,destination_port,
				create_no);
			u_char *nick=NULL;
			if (conn!=NULL)
				nick=conn->owner;		
			urldecode (line_tokens[3]);
			log_event(nick, "Changed display name to [%s]", line_tokens[3]);
		}
	}
	else
	{
		log_debug (0, "Unable to parse PRP correcty");
		log_debug (0, "Line read: %s", next_line);
		dump_tokens (line_tokens);	
		return NOT_MSN;
	}
	return rc;
}

/* LST - list of contacts */
int handler_msn_lst (u_char *raw, int length, ip_address source,
				  u_short source_port, ip_address destination, u_short destination_port)
{
	int rc, nt;
	log_debug (4, "Entry into handler_msn_lst");
	rc= get_new_line_malloc (&next_line, raw, length);
	if (rc<0)
		return rc;
	nt= get_tokens (next_line, &line_tokens, 0); /* Split in all tokens */
	if (nt>=3) 
	{
		struct msn_connection *conn = get_or_create_msn_connection
			(&source,source_port,&destination,destination_port,
			create_no);
		u_char *nick=NULL;
		if (conn!=NULL)
			nick=conn->owner;
		if (strlen ((char *) line_tokens[1])<3)
		{
			log_debug (0, "Unable to parse LST correctly");
			return NOT_MSN;
		}
		log_contact(nick,line_tokens[1]+2);
	}
	else
	{
		log_debug (0, "Unable to parse LST correcty");
		log_debug (0, "Line read: %s", next_line);
		dump_tokens (line_tokens);	
		return NOT_MSN;
	}
	return rc;
}
