/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance *sr) {
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet/* lent */,
                     unsigned int len,
                     char *interface/* lent */) {
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n", len);

    /* fill in code here */
    if (sizeof(sr_ethernet_hdr_t) > len) {
        fprintf(stderr, "Not a valid ethernet header \n");
    }

    uint16_t ether_type = ethertype(packet);

    if (ether_type == ethertype_ip) {
        sr_handle_ip_packet(sr, packet, len, interface);

    } else if (ether_type == ethertype_arp) {
        sr_handle_arp_packet(sr, packet, len, interface);
    }

}/* end sr_ForwardPacket */

void sr_handle_ip_packet(struct sr_instance *sr,
                         uint8_t *packet/* lent */,
                         unsigned int len,
                         char *interface/* lent */) {

    /* sanity check for IP */
    if (pass_sanity_check(packet, len, ethertype_ip, 0)) {
        sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
        struct sr_if *dest_if = get_interface_through_ip(sr, ip_header->ip_dst);

        if (dest_if) {/* to a router interface*/
            uint8_t ip_proto = ip_protocol((uint8_t *)ip_header);

            if (ip_proto == ip_protocol_icmp) { /* is an ICMP echo request*/
                /* sanity check for ICMP */
                if (pass_sanity_check(packet, len, ethertype_ip, ip_protocol_icmp)) {
                    sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *) (packet +
                                                                    sizeof(sr_ip_hdr_t) +
                                                                    sizeof(sr_ethernet_hdr_t));
                    /* check echo request */
                    if (icmp_header->icmp_type != 8) {
                        fprintf(stderr, "Invalid ICMP echo request");
                        return;
                    }
                    /* Echo reply. Send (type 0, code 0) */
                    send_ICMP_msg(sr, packet, len, interface, 0, 0);

                }

            } else { /* contains a TCP or UDP payload */
                /* Port unreachable. Send (type 3, code 3)*/
                send_ICMP_msg(sr, packet, len, interface, 3, 3);
            }

        } else { /*not to a router interface */
            /* Decrement the TTL by 1, and recompute the packet checksum over the modified header.*/
            ip_header->ip_ttl--;
            ip_header->ip_sum = 0;
            ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

            /* Time exceed. Send (type 11, code 0)*/
            if (ip_header->ip_ttl <= 0) {
                send_ICMP_msg(sr, packet, len, interface, 11, 0);
            }

            struct sr_rt *next_hop_ip = find_longest_prefix_match(sr, ip_header->ip_dst);

            /* Destination net unreachable. Send (type 3, code 0) */
            if (!next_hop_ip) {
                send_ICMP_msg(sr, packet, len, interface, 3, 0);
            }

            struct sr_if *next_if = sr_get_interface(sr, next_hop_ip->interface);
            struct sr_arpentry *next_hop = sr_arpcache_lookup(&(sr->cache), ntohl(ip_header->ip_dst));

            if (!next_hop) {
                /* add the packet to the queue of packets waiting on this ARP request.*/
                struct sr_arpreq *arp_req = sr_arpcache_queuereq(&(sr->cache),
                                                                 ntohl(ip_header->ip_dst),
                                                                 packet, len,
                                                                 next_hop_ip->interface);
                handle_arpreq(sr, arp_req);
            } else { /* send an ARP request for the next-hop IP */
                sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *)packet;
                memcpy(eth_header->ether_dhost, next_hop->mac, ETHER_ADDR_LEN);
                memcpy(eth_header->ether_shost, next_if->addr,
                       ETHER_ADDR_LEN);
                free(next_hop);
                sr_send_packet(sr, packet, len, next_if->name);
            }
        }
    }



}

void sr_handle_arp_packet(struct sr_instance *sr,
                          uint8_t *packet/* lent */,
                          unsigned int len,
                          char *interface/* lent */) {
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    struct sr_if *source_if = sr_get_interface(sr,interface);
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    struct sr_if *target_if = get_interface_through_ip(sr,arp_hdr->ar_tip);
    if(target_if && ntohs(arp_hdr->ar_op) == arp_op_request){
        fprintf(stdout,"case1.1: ------arp request------\n");
        unsigned long length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        uint8_t *arp_reply = (unit8_t *)malloc(length);
        
        build_ether_header((sr_ethernet_hdr_t *)arp_reply, eth_hdr->ether_shost, source_if->addr, ethertype_arp);
        sr_arp_hdr_t *arp_reply_hdr = (sr_arp_hdr_t *)(arp_reply + sizeof(sr_ethernet_hdr_t));
        build_arp_header(arp_reply_hdr, source_if, arp_hdr, arp_op_reply);

        sr_send_packet(sr,arp_reply,length,source_if->name);
        free(arp_reply);
    }else if(target_if && ntohs(arp_hdr->ar_op) == arp_op_reply){
        fprintf(stdout,"---------- case1.2: arp_response");
        struct sr_arpreq *arp_req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, ntohl(arp_hdr->ar_sip));
        if(arp_req){
            struct sr_packact* packet_pointer;
            for(packet_pointer=arp_req->packets;packet_pointer!=NULL;packet_pointer=packet_pointer->next){
                sr_ethernet_hdr_t *arp_req_eth = (sr_ethernet_hdr_t *)packet_pointer->buf;
                build_ether_header(arp_req_eth, arp_hdr->ar_sha, source_if->addr, ethertype(packet_pointer->buf) );
                sr_send_packet(sr,packet_pointer->buf,packet_pointer->len,packet_pointer->iface);
            }
            sr_arpcache_destroy(&(sr->cache),arp_req);
        }
    }
}

/*
 *  Sanity-check the packet
 * */
int pass_sanity_check(uint8_t *packet, unsigned int len, uint16_t ether_type, uint8_t is_icmp) {
    int base_length = sizeof(sr_ethernet_hdr_t);

    if (ether_type == ethertype_ip) {

        base_length += sizeof(sr_ip_hdr_t);
        if (!is_icmp) {/* IP */
            /* check min length */
            if (base_length > len) {
                fprintf(stderr, "Not a valid IP header\n");
                return 0;
            }

            /* has correct checksum */
            sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
            uint16_t org_sum = ip_header->ip_sum;
            ip_header->ip_sum = 0;
            ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
            if (org_sum != ip_header->ip_sum) {
                fprintf(stderr, "Wrong checksum for IP header\n");
                return 0;
            }
        } else { /* ICMP */
            /* check min length */
            base_length += sizeof(sr_icmp_hdr_t);
            if (base_length > len) {
                fprintf(stderr, "Not a valid ICMP header\n");
                return 0;
            }

            /* has correct checksum */
            sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *) (packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
            uint16_t org_sum = icmp_header->icmp_sum;
            icmp_header->icmp_sum = 0;
            icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_hdr_t));
            if (org_sum != icmp_header->icmp_sum) {
                fprintf(stderr, "Wrong checksum for ICMP header\n");
                return 0;
            }
        }

    } else if (ether_type == ethertype_arp) { /* ARP */
         /*check min length */
        base_length += sizeof(sr_arp_hdr_t);
        if (base_length > len) return 0;
    } else return 0;

    return 1;
}

struct sr_if *get_interface_through_ip(struct sr_instance *sr, uint32_t dest_addr) {
    for (struct sr_if *pos = sr->if_list; pos != NULL; pos = pos->next) {
        if (dest_addr == pos->ip) return pos;
    }
    return NULL;
}

void send_ICMP_msg(struct sr_instance *sr,
                   uint8_t *packet,
                   unsigned int len,
                   char *interface,
                   uint8_t type, uint8_t code) {
    uint8_t *icmp_msg = NULL;

    unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    struct sr_if *ifs = sr_get_interface(sr, interface);
    sr_ethernet_hdr_t *packet_eth = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t *packet_ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    if (type == 0) { /* Echo reply (type 0)*/

        /* ethernet header */
        sr_ethernet_hdr_t *icmp_msg_eth = (sr_ethernet_hdr_t *)packet;
        build_ether_header(icmp_msg_eth, (uint8_t *) packet_eth->ether_shost,
                           (uint8_t *) packet_eth->ether_dhost, ethertype_ip);

        /* ip header */
        sr_ip_hdr_t *icmp_msg_ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
        build_ip_header(icmp_msg_ip, icmp_msg_ip->ip_len,
                        packet_ip->ip_dst, packet_ip->ip_src, ip_protocol_icmp);

        /*  icmp header */
        sr_icmp_hdr_t *icmp_msg_icmp = (sr_icmp_hdr_t *) (icmp_msg_ip + sizeof(sr_ip_hdr_t));
        icmp_msg_icmp->icmp_type = type;
        icmp_msg_icmp->icmp_code = code;
        icmp_msg_icmp->icmp_sum = 0;
        new_len = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
        icmp_msg_icmp->icmp_sum = cksum(icmp_msg_icmp, (int )new_len);

        /* send */
        sr_send_packet(sr, packet, len, interface);

    } else if (type == 3 || type == 11) {
        icmp_msg = (uint8_t *) malloc(new_len);

        /* ethernet header */
        sr_ethernet_hdr_t *icmp_msg_eth = (sr_ethernet_hdr_t *)icmp_msg;
        build_ether_header(icmp_msg_eth, (uint8_t *) packet_eth->ether_shost, ifs->addr, ethertype_ip);

        /* ip header */
        sr_ip_hdr_t *icmp_msg_ip = (sr_ip_hdr_t *)(icmp_msg + sizeof(sr_ethernet_hdr_t));
        memcpy(icmp_msg_ip, packet_ip, sizeof(sr_ip_hdr_t));
        build_ip_header(icmp_msg_ip, htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t)),
                        ifs->ip, packet_ip->ip_src, ip_protocol_icmp);

        /* ICMP header */
        sr_icmp_t3_hdr_t *icmp_msg_icmp = (sr_icmp_t3_hdr_t *) (icmp_msg_ip + sizeof(sr_ip_hdr_t));
        memcpy(icmp_msg_icmp->data, packet_ip, ICMP_DATA_SIZE);
        build_icmp_header(icmp_msg_icmp, type, code, sizeof(sr_icmp_t3_hdr_t));

        /* send */
        sr_send_packet(sr, icmp_msg, new_len, interface);
        free(icmp_msg);
    }
}

struct sr_rt *find_longest_prefix_match(struct sr_instance *sr, uint32_t dest_addr) {
    struct sr_rt *longest_match = sr->routing_table;

    for (struct sr_rt *r_table = sr->routing_table; r_table != NULL; r_table = r_table->next) {
        uint32_t d1 = ntohl(dest_addr) & r_table->mask.s_addr;
        if (ntohl(r_table->gw.s_addr) == d1) {
            if(r_table->mask.s_addr > longest_match->mask.s_addr) {
                longest_match = r_table;
            }
        }
    }

    return longest_match;
}

char *find_longest_prefix_name(struct sr_instance *sr, uint32_t dest_addr) {
    struct sr_rt *longest_match = find_longest_prefix_match(sr, dest_addr);
    return longest_match == NULL ? NULL: longest_match->interface;
}

void build_ether_header(sr_ethernet_hdr_t *icmp_msg_eth, uint8_t *dhost, uint8_t *shost, uint16_t type) {
    memcpy(icmp_msg_eth->ether_dhost, dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(icmp_msg_eth->ether_shost, shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    icmp_msg_eth->ether_type = htons(type);
}

void build_ip_header(sr_ip_hdr_t *icmp_msg_ip, uint16_t ip_len, const uint8_t *src, const uint8_t *dst, uint8_t ip_p) {
    icmp_msg_ip->ip_len = ip_len;
    icmp_msg_ip->ip_src = src;
    icmp_msg_ip->ip_dst = dst;
    icmp_msg_ip->ip_ttl = INIT_TTL;
    icmp_msg_ip->ip_p = ip_p;
    icmp_msg_ip->ip_sum = 0;
    icmp_msg_ip->ip_sum = cksum(icmp_msg_ip, sizeof(sr_ip_hdr_t));
}

void build_icmp_header(sr_icmp_t3_hdr_t *icmp_msg_icmp, uint8_t type, uint8_t code, int len) {
    icmp_msg_icmp->icmp_type = type;
    icmp_msg_icmp->icmp_code = code;
    icmp_msg_icmp->icmp_sum = 0;
    icmp_msg_icmp->icmp_sum = cksum(icmp_msg_icmp, len);
}

void build_arp_header(sr_arp_hdr_t *reply_arp_hdr, struct sr_if* source_if, sr_arp_hdr_t *arp_hdr, unsigned short type) {
  memcpy(reply_arp_hdr, arp_hdr, sizeof(sr_arp_hdr_t));
  reply_arp_hdr->ar_op = htons(type);
  /* scource */
  memcpy(reply_arp_hdr->ar_sha, source_if->addr, ETHER_ADDR_LEN);
  reply_arp_hdr->ar_sip = source_if->ip;
  /* destination*/
  memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  reply_arp_hdr->ar_tip = arp_hdr->ar_sip;
}