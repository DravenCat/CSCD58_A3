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

static int pass_sanity_check(uint8_t *packet, unsigned int len, uint16_t ether_type, uint8_t is_icmp);

static void sr_handle_ip_packet(struct sr_instance *sr,
                                uint8_t *packet/* lent */,
                                unsigned int len,
                                char *interface/* lent */);

static void sr_handle_arp_packet(struct sr_instance *sr,
                                 uint8_t *packet/* lent */,
                                 unsigned int len,
                                 char *interface/* lent */);

static struct sr_if *get_interface_through_ip(struct sr_instance *sr, uint32_t dest_addr);
static void send_packet(struct sr_instance *sr,
                        uint8_t *packet,
                        unsigned int len,
                        char *interface,
                        uint8_t type, uint8_t code, struct sr_if *dest_if);
static struct sr_rt *find_longest_prefix_match(struct sr_instance *sr, uint32_t dest_addr);

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

    //sanity check for IP
    if (pass_sanity_check(packet, len, ethertype_ip, 0)) {
        sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
        struct sr_if *dest_if = get_interface_through_ip(sr, ip_header->ip_dst);

        if (dest_if) {// to a router interface
            uint8_t ip_proto = ip_protocol((uint8_t *)ip_header);

            if (ip_proto == ip_protocol_icmp) { // is an ICMP echo request
                //sanity check for ICMP
                if (pass_sanity_check(packet, len, ethertype_ip, ip_protocol_icmp)) {
                    sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *) (packet +
                                                                    sizeof(sr_ip_hdr_t) +
                                                                    sizeof(sr_ethernet_hdr_t));
                    // check echo request
                    if (icmp_header->icmp_type != 8) {
                        fprintf(stderr, "Invalid ICMP echo request");
                        return;
                    }
                    //Echo reply. Send (type 0, code 0)
                    send_packet(sr, packet, len, interface, 0, 0, dest_if);

                }

            } else { // contains a TCP or UDP payload
                // Port unreachable. Send (type 3, code 3)
                send_packet(sr, packet, len, interface, 3, 3, dest_if);
            }

        } else { //not to a router interface
            // Decrement the TTL by 1, and recompute the packet checksum over the modified header.
            ip_header->ip_ttl--;
            ip_header->ip_sum = 0;
            ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));

            // Time exceed. Send (type 11, code 0)
            if (ip_header->ip_ttl <= 0) {
                send_packet(sr, packet, len, interface, 11, 0, dest_if);
            }

            struct sr_rt *next_hop_ip = find_longest_prefix_match(sr, ip_header->ip_dst);

            //Destination net unreachable. Send (type 3, code 0)
            if (!next_hop_ip) {
                send_packet(sr, packet, len, interface, 3, 0, dest_if);
            }

            struct sr_if *next_if = sr_get_interface(sr, next_hop_ip->interface);
            struct sr_arpentry *next_hop = sr_arpcache_lookup(&(sr->cache), ntohl(ip_header->ip_dst));

            if (!next_hop) {
                //add the packet to the queue of packets waiting on this ARP request.
                struct sr_arpreq *arp_req = sr_arpcache_queuereq(&(sr->cache),
                                                                 ntohl(ip_header->ip_dst),
                                                                 packet, len,
                                                                 next_hop_ip->interface);
                handle_arpreq(sr, arp_req);
            } else { // send an ARP request for the next-hop IP
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
}

/*
 *  Sanity-check the packet
 * */
int pass_sanity_check(uint8_t *packet, unsigned int len, uint16_t ether_type, uint8_t is_icmp) {
    int base_length = sizeof(sr_ethernet_hdr_t);

    if (ether_type == ethertype_ip) {

        base_length += sizeof(sr_ip_hdr_t);
        if (!is_icmp) {// IP
            // check min length
            if (base_length > len) {
                fprintf(stderr, "Not a valid IP header\n");
                return 0;
            }

            // has correct checksum
            sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
            uint16_t org_sum = ip_header->ip_sum;
            ip_header->ip_sum = 0;
            ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
            if (org_sum != ip_header->ip_sum) {
                fprintf(stderr, "Wrong checksum for IP header\n");
                return 0;
            }
        } else { // ICMP
            // check min length
            base_length += sizeof(sr_icmp_hdr_t);
            if (base_length > len) {
                fprintf(stderr, "Not a valid ICMP header\n");
                return 0;
            }

            // has correct checksum
            sr_icmp_hdr_t *icmp_header = (sr_icmp_hdr_t *) (packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
            uint16_t org_sum = icmp_header->icmp_sum;
            icmp_header->icmp_sum = 0;
            icmp_header->icmp_sum = cksum(icmp_header, sizeof(sr_icmp_hdr_t));
            if (org_sum != icmp_header->icmp_sum) {
                fprintf(stderr, "Wrong checksum for ICMP header\n");
                return 0;
            }
        }

    } else if (ether_type == ethertype_arp) { // ARP
        // check min length
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

void send_packet(struct sr_instance *sr,
                 uint8_t *packet,
                 unsigned int len,
                 char *interface,
                 uint8_t type, uint8_t code, struct sr_if *dest_if) {

}

struct sr_rt *find_longest_prefix_match(struct sr_instance *sr, uint32_t dest_addr) {

}