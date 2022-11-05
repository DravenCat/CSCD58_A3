/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

int pass_sanity_check(uint8_t *packet, unsigned int len, uint16_t ether_type);
void sr_handle_ip_packet(struct sr_instance *sr,
                         uint8_t *packet/* lent */,
                         unsigned int len,
                         char *interface/* lent */);

void sr_handle_arp_packet(struct sr_instance *sr,
                          uint8_t *packet/* lent */,
                          unsigned int len,
                          char *interface/* lent */);
struct sr_if *get_interface_through_ip(struct sr_instance *sr, uint32_t dest_addr);
struct sr_rt *find_longest_prefix_match(struct sr_instance *sr, uint32_t dest_addr);
char *find_longest_prefix_name(struct sr_instance *sr, uint32_t dest_addr);
void build_ether_header(sr_ethernet_hdr_t *icmp_msg_eth, uint8_t *dhost, uint8_t *shost, uint16_t type);
void build_ip_header(sr_ip_hdr_t *icmp_msg_ip, uint16_t ip_len, uint32_t src, uint32_t dst, uint8_t ip_p);
void build_icmp_type3_header(sr_icmp_t3_hdr_t *icmp_msg_icmp, uint8_t type, uint8_t code, uint8_t *data);
void build_icmp_header(sr_icmp_hdr_t *icmp_msg_icmp, uint8_t type, uint8_t code, int len);
void build_arp_header(sr_arp_hdr_t *arp_header, struct sr_if* interface, sr_arp_hdr_t *arp_hdr, unsigned short type);
void send_ICMP_msg(struct sr_instance *sr,
                   uint8_t *packet,
                   unsigned int len,
                   char *interface,
                   uint8_t type, uint8_t code, struct sr_if *eface, struct sr_if *ipface);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
