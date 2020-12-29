#ifndef _DNS_H_
#define _DNS_H_

#include "dnsprotocol.h"

dns_qurry_ret do_dns_query(char * ipaddr, int dns_port, char * domain_name, int verbose);

#endif
