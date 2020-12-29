#include "dns.h"
#include "debug.h"
#include "dnsprotocol.h"
#include "dohprotocol.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define DEFAULT_DNS_SERVER "1.1.1.1"
#define DEFAULT_UNSECURE_DNS_PORT 53
#define DEFAULT_SECURE_DNS_PORT 453
#define TIMEOUT_SECOND 3

static int sockfd = -1;

static int interface_initialize(int type);
static int interface_deinitialize(void);

/* currently, only IPv4 supported. */

dns_qurry_ret do_dns_query(char * ipaddr, int dns_port, char * domain_name, int verbose) {
    if(interface_initialize(2) != 0) {
        debug("interface initialization failed");
        return E_SYS_ERR;
    }
    
    struct sockaddr_in addrstruct;
    memset(&addrstruct, 0, sizeof(addrstruct));

    if (ipaddr == NULL) {
        ipaddr = DEFAULT_DNS_SERVER;
    }

    if (dns_port < 0 || dns_port > 65535) {
        dns_port = DEFAULT_UNSECURE_DNS_PORT;
    }

    addrstruct.sin_family = AF_INET;
    addrstruct.sin_port = htons(dns_port);
    addrstruct.sin_addr.s_addr = inet_addr(ipaddr);

    if(addrstruct.sin_addr.s_addr == INADDR_NONE) {
        error("Given DNS server address invalid");
        return E_IP_ERROR;
    }

    /* set socket timeout */
    struct timeval tv;
    tv.tv_sec = TIMEOUT_SECOND;
    tv.tv_usec = 0;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) != 0) {
        error("Set timeout parameter failed");
        return E_SYS_ERR;
    }

    /* reserved for DOH query */

    fprintf(stdout, "Falied to query through HTTPS, falling back to traditional DNS\n");
    unsecure_dns_query(sockfd, &addrstruct, domain_name, verbose);

    return DNS_SUCCESS;
}

/*
    type: 1 for TCP (DNS over HTTPS)
          2 for UDP (Traditional DNS query)
 */
static int interface_initialize(int type) {
    if (type == 2) {
        if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            error("socket open failed");
            return -1;
        }
    }
    else if (type == 1) {
        /* reserved for DOH query */
        return 0;
    }
    else {
        debug("Incorrect type");
        return -1;
    }
    return 0;
}

static int interface_deinitialize(void) {
    if(sockfd == -1) {
        error("socket not initialized");
        return -1;
    }
    else {
        close(sockfd);
        return 0;
    }

    return 0;
}