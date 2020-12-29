#ifndef _DNSPROTOCOL_H_
#define _DNSPROTOCOL_H_

#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#define PORT_DNS_UNENCYPTED 53

struct DNS_answer {
    uint32_t name;
    int length;
};

struct DNS_answerList {
    int answer_count;
    struct DNS_answer ** DNS_answers;
};

struct DNS_config {
    int server_port;
    char * q_domain_name;
    int q_domain_name_length;
    struct DNS_answerList domain_answers;
    uint16_t ID;
    uint8_t QR_flag;
    uint8_t OpCode;
    uint8_t AA_flag;
    uint8_t TC_flag;
    uint8_t RD_flag;
    uint8_t RA_flag;
    uint8_t Z;
    uint8_t Rcode;
    uint16_t UDP_payload_size;
    uint8_t Extended_Rcode;
    uint8_t EDNS0_ver;
    uint8_t D0_bit;
};

typedef enum {
    E_SYS_ERR,
    E_PACKET_CONFIG_ERROR,
    E_IP_ERROR,
    E_PORT_ERROR,
    E_NO_RESPONSE_ERROR,
    E_QUERY_SEND_ERROR,
    E_DOMAIN_NOT_EXSIT_ERROR,
    DNS_SUCCESS = 0
} dns_qurry_ret;

dns_qurry_ret unsecure_dns_query(int sockfd, struct sockaddr_in * addr, char * domain_name, int verbose);

#endif