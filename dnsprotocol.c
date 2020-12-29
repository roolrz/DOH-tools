/* Conventional DNS protocol, when DOH unavaiable, fallback to this */ 

/* RFC 1035 implemented here */

#include "debug.h"
#include "dnsprotocol.h"
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>

#define UDP_PKT_SIZE 4096

#ifdef __APPLE__
// Apple version of stdlib doesn't include min() function
#define min(a,b) (((a)<(b))?(a):(b))
#endif

/**************************************
Traditional DNS query packet structure
            +-------------+
            |    Header   |
            +-------------+
            |   Question  |
            +-------------+
            |    Answer   |
            +-------------+
            |  Authority  |
            +-------------+
            |  Additional |
            +-------------+
***************************************/

enum RRtype {
    A       = 1, // a host address
    NS      = 2, // an authoritative name server
    MD      = 3, // a mail destination (Obsolete - use MX)
    MF      = 4, // a mail forwarder (Obsolete - use MX)
    CNAME   = 5, // the canonical name for an alias
    SOA     = 6, // marks the start of a zone of authority
    MB      = 7, // a mailbox domain name (EXPERIMENTAL)
    MG      = 8, // a mail group member (EXPERIMENTAL)
    MR      = 9, // a mail rename domain name (EXPERIMENTAL)
    NULL_T  = 10,// a null RR (EXPERIMENTAL)
    WKS     = 11,// a well known service description
    PTR     = 12,// a domain name pointer
    HINFO   = 13,// host information
    MINFO   = 14,// mailbox or mail list information
    MX      = 15,// mail exchange
    TXT     = 16,// text strings

    AXFR    = 252,// A request for a transfer of an entire zone (Only used in query field)
    MAILB   = 253,// A request for mailbox-related records (MB, MG or MR) (Only used in query field)
    MAILA   = 254,// A request for mail agent RRs (Obsolete - see MX) (Only used in query field)
    UNDEF   = 255 // A request for all records (Only used in query field)
};

enum ClassVal {
    IN = 1, // the internet
    CS = 2, // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    CH = 3, // the CHAOS class
    HS = 4  // Hesiod [Dyer 87]
};

enum HeaderOpCode {
    STD_QUERY = 0,  // a standard query
    INV_QUERY = 1,  // a inverse query
    SRV_STATUS= 2  // a server status request
};

enum HeaderRCode {
    NO_ERR = 0, // no error condition
    FORMAT_ERR = 1, // format error
    SERVER_FAILURE = 2,
    NAME_ERROR = 3,
    NOT_SUPPORTED = 4,
    REFUSED = 5
};

/********************************************************
          DNS Header structure (Network byte order)
      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                       ID                      |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   OpCode  |AA|TC|RD|RA|    Z   |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                 Question Count                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                  Answer Count                 |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                Authority Count                |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                Additional Count               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
********************************************************/
struct DNS_Header {
    uint16_t id; // Since this tool do not sent multiple DNS request at the same time, using constant here is OK

    union {
        uint16_t rcode:4;
        uint16_t z:3;
        uint16_t ra:1;
        uint16_t rd:1;
        uint16_t tc:1;
        uint16_t aa:1;
        uint16_t opcode:4;
        uint16_t qr:1;
        uint16_t options;
    };

    uint16_t qcount;
    uint16_t anscount;
    uint16_t authcount;
    uint16_t addicount;
};

/********************************************************
                  DNS Question structure
      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    .                     Qname                     .
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     Qtype                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     Qclass                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
********************************************************/
#pragma pack(push,1)
struct DNS_Question {
    uint16_t qtype;
    uint16_t qclass;
};
#pragma pack(pop)

/********************************************************
                    DNS Answer structure
      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    .                     Aname                     .
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     Atype                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     Aclass                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     Rlength                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    .                     Rdata                     .
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
********************************************************/
#pragma pack(push,1)
struct DNS_RRpayload {
    uint16_t Rtype;
    uint16_t Rclass;
    uint32_t ttl;
    uint16_t Rlength;
};
#pragma pack(pop)
/*******************************************************
                DNS Authority structure
      0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    .                     Mname                     .
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    .                     Rname                     .
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    serial                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    refresh                    |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     retry                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    expire                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    minimum                    |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
********************************************************/
#pragma pack(push,1)
struct DNS_Authority {
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
};
#pragma pack(pop)

#pragma pack(push,1)
struct DNS_AdditionalPkt {
    uint8_t name;
    uint16_t type;
    uint16_t size;
    uint8_t ext_rcode;
    uint8_t edns0_ver;
    union {
        uint16_t reserved:15;
        uint16_t d0:1;
        uint16_t z_options;
    };
    uint16_t datalen;
};
#pragma pack(pop)

struct DNS_pkt {
    void * payload;
    int length;
};

static int dns_header_builder(struct DNS_config * config, struct DNS_pkt * pkt) {
    struct DNS_Header header;
    memset(&header, 0, sizeof(header));
    header.id = htons(config->ID);

    if(config->QR_flag)
        header.qr = 1;
    else
        header.qr = 0;

    header.opcode = config->OpCode;

    if(config->AA_flag)
        header.aa = 1;
    else
        header.aa = 0;
    
    if(config->TC_flag)
        header.tc = 1;
    else
        header.tc = 0;

    if(config->RD_flag)
        header.rd = 1;
    else
        header.rd = 0;

    if(config->RA_flag)
        header.ra = 1;
    else
        header.ra = 0;

    header.z = config->Z;
    header.rcode = config->Rcode;

    header.options = htons(header.options);

    header.qcount = htons(1);
    header.anscount = htons(0);
    header.authcount = htons(0);
    header.addicount = htons(1);

    void * payload = malloc(sizeof(header));
    if (payload == NULL) {
        error("malloc failed");
        return -1;
    }
    memcpy(payload, (void *)&header, sizeof(header));

    pkt->payload = payload;
    pkt->length = sizeof(header);

    return 0;
}

static int dns_question_builder(struct DNS_config * config, struct DNS_pkt * pkt) {
    if (config->q_domain_name == NULL || config->q_domain_name_length == 0) {
        error("Domain name empty");
    }
    char * p_str_start = config->q_domain_name;
    int len = config->q_domain_name_length;
    char * p_str_tail = p_str_start + len - 1;
    char * name = malloc(len+2);

    if (name == NULL) {
        error("malloc error");
        return -1;
    }

    *(name+len+1) = 0;
    char * p_out = name + len;
    int count = 0;
    for (char * ptr = p_str_tail; ptr >= p_str_start; ptr--, p_out--) {
        if (*ptr == '.') {
            *p_out = count;
            count = 0;
            continue;
        }
        count++;
        *p_out = *ptr;
    }
    *name = count;

    struct DNS_Question question;
    question.qclass = htons(IN);
    question.qtype = htons(A);

    void * payload = malloc(len + 2 + sizeof(question));
    if (payload == NULL) {
        error("malloc error");
        if(name)
            free(name);
        return -1;
    }
    memcpy(payload, name, len+2);
    memcpy(payload+len+2, &question, sizeof(question));

    free(name);

    pkt->payload = payload;
    pkt->length = len+2+sizeof(question);

    return 0;
}

static int dns_additional_builder(struct DNS_config * config, struct DNS_pkt * pkt) {
    struct DNS_AdditionalPkt add_pkt;
    memset(&add_pkt, 0, sizeof(add_pkt));
    add_pkt.name = 0;
    add_pkt.type = htons(41);
    add_pkt.size = htons(config->UDP_payload_size);
    add_pkt.ext_rcode = config->Extended_Rcode;
    add_pkt.edns0_ver = config->EDNS0_ver;
    if (config->D0_bit)
        add_pkt.d0 = 1;
    else
        add_pkt.d0 = 0;
    add_pkt.z_options = htons(add_pkt.z_options);
    add_pkt.datalen = htons(0);

    void * payload = malloc(sizeof(add_pkt));
    if(payload == NULL) {
        error("malloc failed");
        return -1;
    }
    memcpy(payload, &add_pkt, sizeof(add_pkt));
    pkt->length = sizeof(add_pkt);
    pkt->payload = payload;

    return 0;
}

static int dns_pkt_builder(struct DNS_config * config, struct DNS_pkt * pkt) {
    int ret = 0;
    struct DNS_pkt headpkt;
    struct DNS_pkt questionpkt;
    struct DNS_pkt addipkt;
    memset(&headpkt, 0, sizeof(headpkt));
    memset(&questionpkt, 0, sizeof(questionpkt));
    memset(&addipkt, 0, sizeof(addipkt));

    if(dns_header_builder(config, &headpkt) != 0) {
        error("package head build error");
        ret = -1;
        goto RET;
    }

    if(dns_question_builder(config, &questionpkt) != 0) {
        error("package question build error");
        ret = -1;
        goto RET;
    }

    
    if(dns_additional_builder(config, &addipkt) != 0) {
        error("package additional build error");
        ret = -1;
        goto RET;
    }
    
    info("combining packages");

    void * payload = malloc(headpkt.length + questionpkt.length + addipkt.length);
    if (payload == NULL) {
        error("malloc failed");
        ret = -1;
        goto RET;
    }

    memcpy(payload, headpkt.payload, headpkt.length);
    memcpy(payload+headpkt.length, questionpkt.payload, questionpkt.length);
    memcpy(payload+headpkt.length+questionpkt.length, addipkt.payload, addipkt.length);

    pkt->payload = payload;
    pkt->length = headpkt.length + questionpkt.length + addipkt.length;

RET:
    if (headpkt.payload)
        free(headpkt.payload);
    if (questionpkt.payload)
        free(questionpkt.payload);
    if (addipkt.payload)
        free(addipkt.payload);
    return ret;
}

static uint32_t name_resolver(const void * p_pkt_start, const void * p_name_start, void ** p_name_end) {
    uint8_t * p_name = (uint8_t *)p_name_start;

    /* skip the compression and name string */
    while(*p_name) {
        if (*p_name == 0xC0) {
            p_name += 2;
        }
        else {
            p_name += 1+*p_name;
        }
    }
    
    /* skip end of name str*/
    p_name += 1;
    /* skip type */
    p_name += 2;
    /* skip class */
    p_name += 2;

    /* skip the compression and name string */
    while(*p_name) {
        if (*p_name == 0xC0) {
            p_name += 2;
        }
        else {
            p_name += 1+*p_name;
        }
    }
    
    /* skip type */
    p_name += 2;
    /* skip class */
    p_name += 2;
    /* skip TTL */
    p_name += 4;

    return *(uint32_t *)(p_name+2);
}

static int dns_pkt_resolver(struct DNS_config * config, struct DNS_pkt * pkt) {
    void * response = malloc(pkt->length);
    void * p_answers = NULL;
    info("Received response of length %d", pkt->length);
    if (response == NULL) {
        error("malloc error");
        return -1;
    }
    int length = pkt->length;
    memcpy(response, pkt->payload, length);

    struct DNS_Header * header = response;
    header->id = ntohs(header->id);
    header->options = ntohs(header->options);
    header->qcount = ntohs(header->qcount);
    header->anscount = ntohs(header->anscount);
    header->authcount = ntohs(header->authcount);
    header->addicount = ntohs(header->addicount);

    if (header->qcount != 1) {
        error("Unable to resolve packet with multiple or none question section");
        return -1;
    }

    void * p_question = response + sizeof(struct DNS_Header);

    uint32_t resolved_question_name = name_resolver(response, p_question, &p_answers);
    if (resolved_question_name == 0) {
        error("Rname resolving error");
        return -1;
    }

    p_answers = malloc((header->qcount+1)*sizeof(void *));
    struct DNS_answer * p_answer = malloc(sizeof(struct DNS_answer));
    *(void **)p_answers = p_answer;
    p_answer->name = resolved_question_name;
    p_answer->length = sizeof(uint32_t);
    
    config->domain_answers.answer_count = header->qcount;
    config->domain_answers.DNS_answers = p_answers;
    config->ID = header->id;


    return 0;
}

static int dns_response_check(struct DNS_config * request, struct DNS_config * response) {
    if (request->ID != response->ID) {
        info("ID mismatch, abandon packet");
        return -1;
    }

    if (strncmp(request->q_domain_name, response->q_domain_name, min(request->q_domain_name_length, response->q_domain_name_length)) != 0) {
        error("Packet poisonous, abandoned. Expected: %s, Reveived: %s", request->q_domain_name, response->q_domain_name);
        return -1;
    }

    return 0;
};

dns_qurry_ret unsecure_dns_query(int sockfd, struct sockaddr_in * addr, char * domain_name, int verbose){
    srand(time(0));
    struct DNS_config config;
    struct DNS_pkt pkt;
    memset(&config, 0, sizeof(config));
    memset(&pkt, 0, sizeof(pkt));
    config.server_port = ntohs(addr->sin_port);
    config.q_domain_name = domain_name;
    config.q_domain_name_length = strlen(domain_name);
    config.ID = rand();
    config.QR_flag = 0; // query packet
    config.OpCode = 0; // standard query
    config.AA_flag = 0; // no need for authoritative answer
    config.TC_flag = 0; // not truncated
    config.RD_flag = 1; // do recursive query
    config.Z = 0; // reserved bit
    config.Rcode = 0; // Only valid in response
    config.Extended_Rcode = 0;
    config.EDNS0_ver = 0;
    config.D0_bit = 0;
    config.UDP_payload_size = UDP_PKT_SIZE;

    if (dns_pkt_builder(&config, &pkt) != 0) {
        if (pkt.payload)
            free(pkt.payload);
        return E_PACKET_CONFIG_ERROR;
    }

    if (verbose) {
        printf("Packet prepared OK, pending send\n");
    }

    int ret = sendto(sockfd, pkt.payload, pkt.length, 0, (const struct sockaddr *)addr, sizeof(struct sockaddr_in)); 
    if (ret != pkt.length) {
        error("send failed, errorno=%d", errno);
        if (verbose)
            printf("send failed, errorno=%d\n", errno);
    
        if (pkt.payload)
            free(pkt.payload);
        return E_QUERY_SEND_ERROR;
    }

    if (verbose) {
        printf("Packet sent, waiting for response\n");
    }

    free(pkt.payload);

    time_t time_start = time(0);

    while (1) {
        if (time(0) > time_start + 5) {
            error("Response timeout\n");
            printf("Waiting for response time out\n");
            return E_NO_RESPONSE_ERROR;
        }

        char buffer[UDP_PKT_SIZE]; 
        int n, len;
        len = sizeof(struct sockaddr_in);
        n = recvfrom(sockfd, (char *)buffer, UDP_PKT_SIZE, MSG_WAITALL, (struct sockaddr *)addr, (socklen_t *)&len);

        if (n == 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            error("Response timeout\n");
            printf("Waiting for response time out\n");
            return E_NO_RESPONSE_ERROR;
        }
        
        if (verbose) {
            printf("Response received, resolving packet\n");
        }

        struct DNS_config config_response;
        struct DNS_pkt pkt_response;
        memset(&config_response, 0, sizeof(config_response));
        memset(&pkt_response, 0, sizeof(pkt_response));
        pkt_response.length = n;
        pkt_response.payload = &buffer;

        if (pkt_response.length <= 0) {
            info("package loss, resending request");
            continue;
        }

        if (dns_pkt_resolver(&config_response, &pkt_response) != 0) {
            error("package resolve failed\n");
            continue;
        }

        if (config_response.domain_answers.answer_count == 0) {
            printf("No such domain name %s\n", config.q_domain_name);
            return E_DOMAIN_NOT_EXSIT_ERROR;
        }

        if (dns_response_check(&config, &config_response) != 0) {
            if (verbose) {
                printf("response check failed, abandoned\n");
            }
            continue;
        }

        struct in_addr addr;
        addr.s_addr = config_response.domain_answers.DNS_answers[0]->name;
        printf("address for %s is %s\n", domain_name, inet_ntoa(addr));
        break;
    }

    return DNS_SUCCESS;
}

