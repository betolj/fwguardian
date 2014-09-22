#include "msnsniffer.h"
#include <stdarg.h>
#include <time.h>
#include <ctype.h>

extern int with_proxy;
extern char last_msg[20480];
int debug_level = 2;

char *gettimestring4log (char *store)
{
	time_t now=time (NULL);
	struct tm stm;
	localtime_r (&now, &stm);
	asctime_r (&stm, store);
	store[24]=0;
	return store;
}

int createdir4nick (u_char *nick)
{
	if (nick && nick[0])
	{
		char dir[1024];
		strcpy (dir, chatlogdir);
		if (dir[strlen (dir)-1]!='/')
			strcat (dir,"/");
		strcat (dir,(char *) nick);
		mkdir (dir,0700);
	}
	return 0;
}

int log_switchboard_end (struct msn_connection *conn)
{
	if (conn!=NULL && conn->log_full_path!=NULL)
	{
		FILE *o=fopen (conn->log_full_path, "a+t");
		if (o!=NULL)
		{
			fprintf (o, "*********************  CHAT END  *************************\n");
			fclose (o);
		}
	}
	return 0;
}

int log_switchboard_event (struct msn_connection *conn, const char *fmt, ...)
{
	char strtme[27];
	char *result;
	int firsttime = 0;

	if (conn == NULL || conn->owner == NULL)
	{
		log_debug (0, "No switchboard or unknown owner, can't log");
		return -1;
	}
	if (conn->log_full_path==NULL && chatlogdir[0]!=0) 
	{
		if (conn->users==NULL || conn->users[0]==NULL)
		{
			log_debug (0, "No known partipants in SB owned by %s, can't log", conn->owner);
			return -1;
		}
		size_t l=strlen (chatlogdir)+1+strlen ((char *) conn->owner)+1+
			strlen ((char *) conn->users[0])+5;
		conn->log_full_path=(char *) malloc (l);
		if (conn->log_full_path==NULL)
			return -1;
		sprintf (conn->log_full_path,"%s/%s/%s.log",chatlogdir,conn->owner,conn->users[0]);
		log_debug (0, "Set SB log name to: %s",conn->log_full_path);
		firsttime = 1;
	}
	gettimestring4log (strtme);

	va_list ap;
	va_start (ap, fmt);
	vasprintf (&result,fmt,ap);
	va_end (ap);

	if (conn->log_full_path!=NULL)
	{
		FILE *o=fopen (conn->log_full_path, "a+t");
		if (o!=NULL)
		{
			if (firsttime)
				fprintf (o, "********************* CHAT START *************************\n");

                        // Try to detect repeted messages (util in spoofed traffic)
                        if (strcmp(result, last_msg)!=0) fprintf (o, "%s | %s\n", strtme, result);
                        strcpy(last_msg, result);

			fclose (o);
		}
		else
		{
			log_debug (0, "Failed to create/append SB event file at [%s]", conn->log_full_path);
		}
	}
	else
	{
		log_debug (0, "SB event: %s", result);
	}
	free (result);
	
	return 0;
}

int delete_profile (u_char *nick)
{			
	if (nick && nick[0]!=0 && chatlogdir[0]!=0)
	{
		log_debug (3, "Deleting profile [%s]", nick);
		char fn[1024];
		sprintf (fn, "%s/%s/profile.log", chatlogdir, nick);
		unlink (fn);
	}
	return 0;
}

int delete_contact_list (u_char *nick)
{			
	if (nick && nick[0]!=0 && chatlogdir[0]!=0)
	{
		log_debug (3, "Deleting contact list for [%s]", nick);
		char fn[1024];
		sprintf (fn, "%s/%s/contact_list.log", chatlogdir, nick);
		unlink (fn);
	}
	return 0;
}

int log_profile (u_char *nick, u_char *payload, int length)
{
	char strtme[27];
	gettimestring4log (strtme);
	log_debug (5, "Entry in log_profile");
	if (nick && nick[0]==0)
		log_debug (3, "Profile for an unknown user, not logged");
	else	
	{
		u_char *prof = (u_char *) malloc (length + 1);
		if (prof == NULL)
			return OUT_OF_MEMORY;
			
		memcpy (prof, payload, length);
		prof[length]=0;
		
		if (chatlogdir[0]==0)
		{
			log_debug (1, "%s | %s | %s", strtme, nick, prof);
		}
		else
		{
			createdir4nick (nick);
			char fn[1024];
			sprintf (fn, "%s/%s/profile.log", chatlogdir, nick);
			FILE *o=fopen (fn, "w");
			// printf ("%s\n",fn);
			if (o!=NULL)
			{
				fwrite (prof, 1, length, o);
				fclose (o);
			}
			else
			{
				log_debug (0, "Failed to create profile file [%s]", fn);
			}
		}
		free (prof);	
	}
	return 0;
}

int log_contact (u_char *nick, u_char *contact)
{
	char strtme[27];
	gettimestring4log (strtme);
	log_debug (5, "Entry in log_contact");
	if (nick && nick[0]==0)
		log_debug (3, "Contact [%s] for an unknown user, not logged", contact);
	else	
	{
		if (chatlogdir[0]==0)
		{
			log_debug (1, "%s | %s | Contact: %s", strtme, nick, contact);
		}
		else
		{
			createdir4nick (nick);
			char fn[1024];
			sprintf (fn, "%s/%s/contact_list.log", chatlogdir, nick);
			FILE *o=fopen (fn, "a+t");
			// printf ("%s\n",fn);
			if (o!=NULL)
			{
				fprintf (o, "%s | %s\n", strtme, contact);
				fclose (o);
			}
			else
			{
				log_debug (0, "Failed to create contact file [%s]", fn);
			}
		}		
	}
	return 0;
}

int log_debug (int level, const char *fmt, ...)
{
	char *result;
	char strtme[27];
	if (level<=debug_level)
	{
		gettimestring4log (strtme);
		va_list ap;
		va_start (ap, fmt);
		vasprintf (&result,fmt,ap);
		va_end (ap);
		if (debuglogdir[0]==0)
		{
			if (!daemonize)
				printf ("%s | %d | %s\n", strtme, level, result);
		}
		else
		{
			char fn[1024];
			time_t now=time (NULL);
			struct tm stm;
			localtime_r (&now, &stm);
			sprintf (fn, "%s/msnsniffer_%04d-%02d-%02d.log", debuglogdir, stm.tm_year, stm.tm_mon, stm.tm_mday);
			FILE *o=fopen (fn, "a+t");
			if (o!=NULL)
			{
				fprintf (o, "%s | %d | %s\n", strtme, level, result);
				fclose (o);
			}
		}
		free (result);
	}
	return 0;
}

int log_event (u_char *nick, const char *fmt, ...)
{
	char *result;
	va_list ap;
	char strtme[27];
	va_start (ap, fmt);
	vasprintf (&result,fmt,ap);
	va_end (ap);
	gettimestring4log (strtme);
	if (nick==NULL || nick[0]==0)
		log_debug (1, "Event for an unknown nick: %s", result);
	else
	{
		if (chatlogdir[0]==0)
		{
			log_debug (1, "Nick [%s] Event: [%s]", nick, result);
		}
		else
		{
			createdir4nick (nick);
			char fn[1024];
			sprintf (fn, "%s/%s/events.log", chatlogdir, nick);
			FILE *o=fopen (fn, "a+t");
			// printf ("%s\n",fn);
			if (o!=NULL)
			{
				fprintf (o, "%s | %s\n", strtme, result);
				fclose (o);
			}
		
		}
	}
	
	free (result);
	return 0;
}

int get_new_line_malloc (u_char **target, u_char *source, int length)
{
		int must_free=0;		
		if (length<2) // No room for \r\n
		{
			log_debug (5, "get_new_line_malloc: line too short.");
			return LINE_INCOMPLETE;
		}		
		if (target!=NULL) 
		{
			if (*target != NULL)
				free (*target);
			*target = (u_char *) malloc (length + 1);
			if (*target == NULL)
				return OUT_OF_MEMORY;
			memset (*target, 0, length+1);
			
		}
	
		u_char *now = source; // Where we are copying from 
		u_char *work = (target==NULL)?NULL:*target; // Where, if anywhere, we are copying to 
		int skipped=0;
		while (skipped<length-2 && *now!='\n' && *now!='\r')
		{		
			if (work!=NULL && *now>=' ')
			{
				*work=*now;
				*work++;
			}
			skipped++;
			*now++;
		}			
		if ( *(now)!='\r' || *(now+1)!='\n') // No \r\n? Not MSN or incomplete
		{
			log_debug (5, "get_new_line_malloc: Incomplete\n");
			log_debug (5, "get_new_line_malloc: Source was: %s\n",source); // TODO: Fix not null-terminated! 
			return -1;
		}
		return skipped+2; // Skip \r\n too
}

/* Note: *line must be zero-terminated (as returned by get_new_line_malloc) */

void dump_tokens (u_char **tokens)
{
	if (tokens==NULL)
		return;
	int i=0;
	while (tokens[i]!=NULL)
	{
		log_debug (0, "Token %d: %s",i, tokens[i]);
		i++;
	}
}

u_char *strcpymalloc (u_char **target, u_char * src)
{
	if (target==NULL)
		return NULL;
	if (*target!=NULL)
		free (*target);
	*target=(u_char *) malloc (strlen ((char *) src)+1);
	if (*target!=NULL)
	{
		strcpy ((char *) *target,(char *) src);
	}
	return *target;
}

void free_array (u_char ***tokens)
{
	if (*tokens!=NULL)
	{
		int i=0;
		while ((*tokens)[i]!=NULL)
		{
			free ((*tokens)[i]);
			i++;
		}
		/* ...free the array itself */
	        free (*tokens);
	}
}

int get_tokens (u_char *line, u_char ***tokens, int max_tokens)
{
	log_debug (5, "entry in get_tokens");
	int capacity = (max_tokens==0)?50:max_tokens;
 
	/* First, delete the tokens if there are any ... */
	free_array(tokens);

	*tokens=(u_char **) malloc (sizeof (u_char *) * (capacity +1)); // Final one is NULL
	if (*tokens==NULL)
		return OUT_OF_MEMORY;

	int num=0; /* Number of tokens added so far */	
	u_char *now = line;
	u_char *newtoken; 
	for (;;)
	{
		size_t i;
		/* Skip spaces and control stuff */
		while (*now<=' ' && *now!=0)
		{
			now++;
		}
					
		if (*now==0) /* End of line */
			break; 
			
		i=0;
		if (max_tokens==num+1 && max_tokens!=0) 
			i=strlen ((char *) now);
		else
		{
			while (now[i]>' ') /* Look ahead, how long is the next token? */
				i++;
		}
		newtoken=(u_char *) malloc (i+1);
		memcpy (newtoken, now, i);
		now = now + i;
		newtoken[i]=0;

		if (num==capacity)
		{
			capacity += 10;
			*tokens = (u_char **) realloc (*tokens, sizeof (u_char *) * (capacity +1));
			if (*tokens==NULL) /* A bit unstable now I'm afraid */
				return OUT_OF_MEMORY;
		}

		(*tokens)[num]=newtoken;

		if ((num==7 && !with_proxy) || (num==12 && with_proxy))
		{
			break;
//			exit (7);
		}

		num++;
	}

	(*tokens)[num]=NULL;
	return num;
}

int get_value_from_hex (char c)
{
	c=toupper (c);
	if (c>='0' && c<='9')
		return c-'0';
	if (c>='A' && c<='F')
		return c-'A';
	return -1;
}

u_char *urldecode (u_char *src)
{
	u_char *tmp = (u_char *) malloc (strlen ((char *) src) + 1);
	u_char *c = src;
	if (tmp==NULL)
		return src;
	memset (tmp, 0, strlen ((char *) src) +1);
	u_char *now = tmp;	
	while (*c)
	{
		if (*c!='%')
		{
			*now = *c;
			now++;
			c++;
		}
		else
		{
			if (*(c+1)==0 || *(c+2)==0) // ?? Doesn't look good.
			{
				free (tmp);
				return src;
			}
			int v1 = get_value_from_hex (* (c+1));
			int v2 = get_value_from_hex (* (c+2));
			if (v1==-1 || v2==-1)
			{
				free (tmp);
				return src;
			}
			*now = (v1*16+v2);
			now++;
			c+=3;
		}
	}
	strcpy ((char *) src, (char *) tmp);
	free (tmp);
	return src;
}
