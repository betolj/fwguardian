/* THE CODE HERE TAKES CARE OF KEEPING TRACKING OF THE INFORMATION WE
   COLLECT ABOUT ONGOING TCP CONNECTIONS */

#include "msnsniffer.h"
   
struct msn_connection *msn_conns_first = NULL;
struct msn_connection *msn_conns_last = NULL;

void add_user_to_sb (struct msn_connection *conn, u_char *user)
{
        if (conn == NULL) return;

	if (conn!=NULL && conn->users!=NULL)
	{
		int i=0;
		while (i<conn->num_users && conn->users[i])
		{
			if (strcmp ((char *) conn->users[i], (char *) user)==0)
				return; // Don't duplicate
			i++;
		}
	}

	log_debug (5, "Adding user [%s] to SB",user);
	conn->users=(u_char **) realloc (conn->users, sizeof (u_char *) * (conn->num_users+1));
	log_debug (5, "Done realloc");

	if (conn->users!=NULL)
	{
		conn->users[conn->num_users]=(u_char *) malloc (strlen ((char *) user) +1 );
		log_debug (5, "Done malloc");	
		strcpy ((char *) conn->users[conn->num_users],(char *) user);
		log_debug (5, "Done strcpy");		
		conn->num_users++;
	}
	log_debug (5, "Done, number of users now = %d",conn->num_users);
}

void clear_msn_connection (struct msn_connection *conn)
{
	log_debug (3, "Clearing connection %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
		conn->IP_A.byte1,conn->IP_A.byte2,conn->IP_A.byte3,conn->IP_A.byte4,
			conn->port_A, conn->IP_B.byte1,
			conn->IP_B.byte2,conn->IP_B.byte3,conn->IP_B.byte4,conn->port_B);	
	if (conn->owner!=NULL)
	{
		free (conn->owner);
		conn->owner=NULL;
	}
	conn->conn_type=type_unknown;
	if (conn->users!=NULL)
	{
		int i=0;
		while (i<conn->num_users)
		{
			free (conn->users[i]);
			i++;
		}
		free (conn->users);
		conn->num_users=0;
	}
	if (conn->pending_A!=NULL)
		free (conn->pending_A);
	if (conn->pending_B!=NULL)
		free (conn->pending_B);
	if (conn->log_full_path!=NULL)
		free (conn->log_full_path);
	conn->pending_A_length=0;
	conn->pending_B_length=0;
	conn->pending_A=NULL;
	conn->pending_B=NULL;		
	conn->log_full_path=NULL;
	conn->whowserver=unknown;
	
}

void set_owner (struct msn_connection *conn, u_char *owner)
{
	if (conn==NULL || owner==NULL)
	{
		log_debug (0, "Entry in set_owner() with NULL parameter(s)");
		return;
	}
	log_debug (5, "Setting owner [%s] to connection %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
		owner, conn->IP_A.byte1,conn->IP_A.byte2,conn->IP_A.byte3,conn->IP_A.byte4,
			conn->port_A, conn->IP_B.byte1,
			conn->IP_B.byte2,conn->IP_B.byte3,conn->IP_B.byte4,conn->port_B);
	
	if (conn->owner != NULL)
	{
		if (strcmp ((char *) conn->owner, (char *) owner))
		{
			log_debug (0, "Warning: Owner change in MSN connection, this looks like a bug");
		}
		else
		{
			log_debug (5, "set_owner(): Owner match, all OK");

		}
	}
	else
	{
		log_debug (5, "(no previous owner)");
	}
	strcpymalloc (&conn->owner, owner);
}

int is_from_A (struct msn_connection *conn, ip_address *ip, int port)
{
	if (conn==NULL)
		return -1;
	if (conn->IP_A.byte1 == ip->byte1 &&
		conn->IP_A.byte2 == ip->byte2 &&
		conn->IP_A.byte3 == ip->byte3 &&
		conn->IP_A.byte4 == ip->byte4 &&
		conn->port_A == port)
	{
			return 1;
	}
	if (conn->IP_B.byte1 == ip->byte1 &&
		conn->IP_B.byte2 == ip->byte2 &&
		conn->IP_B.byte3 == ip->byte3 &&
		conn->IP_B.byte4 == ip->byte4 &&
		conn->port_B == port)
	{
			return 0;
	}
	return -1; // Not from any of them */
	

}

int is_from_server (struct msn_connection *conn, ip_address *ip, int port)
{
	if (conn==NULL)
		return -1;
	if (conn->IP_A.byte1 == ip->byte1 &&
		conn->IP_A.byte2 == ip->byte2 &&
		conn->IP_A.byte3 == ip->byte3 &&
		conn->IP_A.byte4 == ip->byte4 &&
		conn->port_A == port)
	{
		if (conn->whowserver==endpointA)
			return 1;
		else 
			return 0;
	}
	if (conn->IP_B.byte1 == ip->byte1 &&
		conn->IP_B.byte2 == ip->byte2 &&
		conn->IP_B.byte3 == ip->byte3 &&
		conn->IP_B.byte4 == ip->byte4 &&
		conn->port_B == port)
	{
		if (conn->whowserver==endpointB)
			return 1;
		else 
			return 0;
	}
	return -1; // Not server and not user?		
}

void set_as_server (struct msn_connection *conn, ip_address *ip, int port)
{
	if (conn==NULL)
		return;
		
	if (conn->IP_A.byte1 == ip->byte1 &&
		conn->IP_A.byte2 == ip->byte2 &&
		conn->IP_A.byte3 == ip->byte3 &&
		conn->IP_A.byte4 == ip->byte4 &&
		conn->port_A == port)
	{
		if (conn->whowserver==endpointB)
		{
			log_debug (0, "Warning: In this connection, the server was previously misidentified");
		}
		conn->whowserver=endpointA;
	}	
	else
	{
		if (conn->whowserver==endpointA)
		{
			log_debug (0, "Warning: In this connection, the server was previously misidentified");
		}
		conn->whowserver=endpointB;
	}
}

int remove_msn_connection (struct msn_connection *conn)
{
	if (conn)
	{
		log_debug (5, "Removing connection from linked list");
		clear_msn_connection (conn);
		if (conn->previous!=NULL)
			conn->previous->next=conn->next;
		if (conn->next!=NULL)
			conn->next->previous=conn->previous;
		if (msn_conns_first == conn)
			msn_conns_first = conn->next;
		if (msn_conns_last == conn)
			msn_conns_last = conn->previous;
		free (conn);
	}
	return 0;
}


struct msn_connection *get_or_create_msn_connection (ip_address *source_ip, int source_port, 
	ip_address *target_ip, int target_port,
	enum e_msn_conn_create create)
{
	struct msn_connection * ipa = msn_conns_first;
	struct msn_connection * auxipa;
	log_debug (5,"get_or_create_msn_connection: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",
			source_ip->byte1,source_ip->byte2,source_ip->byte3,source_ip->byte4,source_port,
			target_ip->byte1,target_ip->byte2,target_ip->byte3,target_ip->byte4,target_port);
	
	int i=0;
	while (ipa)
	{	
		log_debug (6,"%d - IPA: %d.%d.%d.%d:%d -> %d.%d.%d.%d:%d",i,
			ipa->IP_A.byte1,ipa->IP_A.byte2,ipa->IP_A.byte3,ipa->IP_A.byte4,ipa->port_A,
			ipa->IP_B.byte1,ipa->IP_B.byte2,ipa->IP_B.byte3,ipa->IP_B.byte4,ipa->port_B);

		if ((ipa->IP_A.byte1 == source_ip->byte1 &&
			ipa->IP_A.byte2 == source_ip->byte2 &&
			ipa->IP_A.byte3 == source_ip->byte3 &&
			ipa->IP_A.byte4 == source_ip->byte4 &&
			ipa->port_A == source_port &&
			ipa->IP_B.byte1 == target_ip->byte1 &&
			ipa->IP_B.byte2 == target_ip->byte2 &&
			ipa->IP_B.byte3 == target_ip->byte3 &&
			ipa->IP_B.byte4 == target_ip->byte4 &&
			ipa->port_B == target_port) ||
			(ipa->IP_A.byte1 == target_ip->byte1 &&
			ipa->IP_A.byte2 == target_ip->byte2 &&
			ipa->IP_A.byte3 == target_ip->byte3 &&
			ipa->IP_A.byte4 == target_ip->byte4 &&
			ipa->port_A == target_port &&
			ipa->IP_B.byte1 == source_ip->byte1 &&
			ipa->IP_B.byte2 == source_ip->byte2 &&
			ipa->IP_B.byte3 == source_ip->byte3 &&
			ipa->IP_B.byte4 == source_ip->byte4 &&
			ipa->port_B == source_port))
		{
			log_debug (6, "Match");

	                // Nomatch connection timeout (3600 per ipa) - for memory protect
	                ipa->connmap_timeout = 0;

			if (create==create_replace)
				clear_msn_connection(ipa);
			log_debug (5, "Connection requested found");
			return ipa;
		}
		else
		{
			log_debug (5, "No match");

	                // Nomatch connection timeout (3600 per ipa) - for memory protect
	                ipa->connmap_timeout++;
		}

	   	if (ipa != NULL) {
                        ipa=ipa->next;
                        if (ipa == msn_conns_last) ipa->next = NULL;
                }

	}
	log_debug (5, "End of ipa list");

        // Remove connections under timeout
        auxipa = NULL;
	log_debug (5, "Delete connections under timeout");
        ipa = msn_conns_first;
        for (; ipa != NULL;) {
              if (auxipa != NULL && auxipa->connmap_timeout >= 3600) remove_msn_connection(auxipa);

              auxipa = ipa;
              ipa = ipa->next;
        }
        if (auxipa != NULL && auxipa->connmap_timeout >= 3600) remove_msn_connection(auxipa);

	if (create==create_yes)
	{
		struct msn_connection * ipa = (struct msn_connection *) malloc (sizeof (struct msn_connection));
		log_debug (5, "Creating new connection, %d", i);
		if (ipa!=NULL)
		{
			if (msn_conns_first==NULL)
				msn_conns_first=ipa;
		
			memset (ipa,0,sizeof (struct msn_connection)); // All zeros is fine
			if (msn_conns_last != NULL)
			{
				msn_conns_last->next=ipa;
				ipa->previous=msn_conns_last;
			}
			msn_conns_last=ipa;
			memcpy (&ipa->IP_A,source_ip,sizeof (struct ip_address));
			ipa->port_A=source_port;
			memcpy (&ipa->IP_B,target_ip,sizeof (struct ip_address));
			ipa->port_B=target_port;				
			ipa->whowserver=unknown;
			ipa->num_users=0;
                        ipa->connmap_timeout = 0;
			ipa->users=NULL;
			ipa->log_full_path=NULL;
			return ipa;
		}
		
	}
        log_debug(5, "Return NULL for MSN Connection");
	return NULL;
}


