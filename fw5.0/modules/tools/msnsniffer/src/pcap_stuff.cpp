/* PCAP related stuff should go here */

#include "msnsniffer.h"

struct datalink_type
{
	int pcap_nr;
	char *name;
	int offset;
} 
dtl [] = { 
	{ DLT_EN10MB, "Ethernet", 14},
	{ DLT_PPP, "PPP", 4},
	{ DLT_PPP_ETHER, "PPPoE", 4},
	{ DLT_LINUX_SLL, "Linux cooked sockets", 16},
	{ -1, NULL, -1}
};
	
	
int get_datalink_type (pcap_t *dh)
{
	return pcap_datalink (dh);
}

int get_datalink_info (pcap_t *dh, char **name, int *offset)
{
	int i = 0;
	int link = pcap_datalink (dh);
	
	while (dtl[i].offset != -1)
	{
		if (link==dtl[i].pcap_nr)
		{
			*name = dtl[i].name;
			*offset = dtl[i].offset;
			return 0;
		}
		i++;
	}
	*name = NULL;
	*offset = -1;
	return -1;
	
}
