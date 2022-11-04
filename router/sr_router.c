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
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

struct sr_if* get_interface_by_ip(struct sr_instance* sr, uint32_t tip);
char* get_interface_by_LPM(struct sr_instance* sr, uint32_t ip_dst);
int sanity_check(uint8_t *buf, unsigned int length);
int handle_chksum(sr_ip_hdr_t *ip_hdr);
void construct_eth_header(uint8_t *buf, uint8_t *dst, uint8_t *src, uint16_t type);
void construct_arp_header(uint8_t *buf, struct sr_if* source_if, sr_arp_hdr_t *arp_hdr, unsigned short type);
void construct_ip_header(uint8_t *buf, uint32_t dst, uint32_t src, uint16_t type);
uint8_t* construct_icmp_header(uint8_t *ip_buf, struct sr_if* source_if, uint8_t type, uint8_t code, unsigned long len);
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
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

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  print_hdrs(packet, len);

  /* fill in code here */

     /* Sanity check*/
    if (pass_sanity_check(packet, len)) {
        /* get the ethernet header type*/
        uint16_t ethtype = ethertype(packet);

        if (ethtype == ethertype_arp) { /* handle arp request*/
            sr_handle_arp_packet(sr, packet, len, interface);
        } else if (ethtype == ethertype_ip) { /* handle ip request*/
            sr_handle_ip_packet(sr, packet, len, interface);
        }
    } else { /* Fail on sanity check*/
        fprintf(stderr, "Fail to pass sanity check\n");
        return;
    }

}/* end sr_ForwardPacket */

/* Sanity check*/
int pass_sanity_check(uint8_t *packet, unsigned int len) {
    int base_length = sizeof(sr_ethernet_hdr_t);
    /* check min length */
    if (base_length > len) {
        fprintf(stderr, "Wrong checksum! Not a valid ethernet header\n");
        return 0;
    }

    uint16_t ether_type = ethertype(packet);
    if (ether_type == ethertype_ip) {/* IP */
        base_length += sizeof(sr_ip_hdr_t);

        /* check min length */
        if (base_length > len) {
            fprintf(stderr, "Wrong checksum! Not a valid IP header\n");
            return 0;
        }

        /* has correct checksum */
        sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
        uint16_t org_sum = ip_header->ip_sum;
        ip_header->ip_sum = 0;
        ip_header->ip_sum = cksum(ip_header, sizeof(sr_ip_hdr_t));
        if (org_sum != ip_header->ip_sum) {
            fprintf(stderr, "Wrong checksum! Wrong checksum for IP header\n");
            return 0;
        }

        uint8_t ip_proto = ip_protocol(packet + sizeof(sr_ethernet_hdr_t));
        if (ip_proto != ip_protocol_icmp) { /* ICMP */
            /* check min length */
            base_length += sizeof(sr_icmp_hdr_t);
            if (base_length > len) {
                fprintf(stderr, "Wrong checksum! Not a valid ICMP header\n");
                return 0;
            }
        }

    } else if (ether_type == ethertype_arp) { /* ARP */
        /*check min length */
        base_length += sizeof(sr_arp_hdr_t);
        if (base_length > len) {
            fprintf(stderr, "Wrong checksum! Not a valid arp header\n");
            return 0;
        }
    } else return 0;

    return 1;
}

/* Handle ip packet */
void sr_handle_ip_packet(struct sr_instance *sr,
                         uint8_t *packet/* lent */,
                         unsigned int len,
                         char *interface/* lent */) {
    sr_ethernet_hdr_t *packet_eth = (sr_ethernet_hdr_t *)packet;
    struct sr_if *iface = sr_get_interface(sr, interface);

    sr_ip_hdr_t *packet_ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if *target_if = get_interface_through_ip(sr, packet_ip->ip_dst);
    fprintf(stdout, "Handling ip request!\n");

    /* the request goes to an existing interface */
    if (target_if) {
        int protocol = ip_protocol(packet+sizeof(sr_ethernet_hdr_t));
        /*   If the packet is an ICMP echo request and its checksum is valid, send an ICMP echo reply to the sending host. */
        if (protocol == ip_protocol_icmp) {

            /* build the ethernet header */
            build_ether_header((sr_ethernet_hdr_t *)packet, (uint8_t *)packet_eth->ether_shost, iface->addr, ethertype_ip);
            /* build the ip header */
            build_ip_header(packet_ip, packet_ip->ip_len,
                            packet_ip->ip_dst, packet_ip->ip_src, ip_protocol_icmp);

            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
            if (icmp_hdr->icmp_type == (uint8_t)8) { /* check whether it is an echo request */
                /* check the checksum */
                uint16_t sum = icmp_hdr->icmp_sum;
                icmp_hdr->icmp_sum = 0;
                icmp_hdr->icmp_sum = cksum(icmp_hdr, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
                if (sum != icmp_hdr->icmp_sum) {
                    fprintf(stderr, "Wrong checksum! Not a valid icmp header\n");
                    return;
                }

                /* build icmp echo response */
                icmp_hdr->icmp_type = 0;
                icmp_hdr->icmp_code = 0;
                icmp_hdr->icmp_sum = 0;
                icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
                fprintf(stdout, "Echo reply (type 0)\n");
                sr_send_packet(sr, packet, len, iface->name);
            }

        /* If the packet contains a TCP or UDP payload, send an ICMP port unreachable to the sending host.*/
        } else if (protocol == ip_protocol_tcp || protocol == ip_protocol_udp) {
            /* Port unreachable. Sent ICMP message with type 3 code 3 */
            send_ICMP_msg(sr, packet, len, interface, 3, 3, iface);
            fprintf(stdout, "Port unreachable (type 3, code 3)\n");
        }

    /*  Packets destined elsewhere should be forwarded using the normal forwarding logic. */
    } else {
        /* Decrement the TTL by 1, and recompute the packet checksum over the modified header.*/
        packet_ip->ip_ttl--;
        packet_ip->ip_sum = 0;
        packet_ip->ip_sum = cksum(packet_ip, sizeof(sr_ip_hdr_t));

        /* Sent if an IP packet is discarded during processing because the TTL field is 0 */
        if (packet_ip->ip_ttl < 0) {
            /* build icmp echo response */
            send_ICMP_msg(sr, packet, len, interface, 11, 0, iface);
            fprintf(stdout, "Time exceeded (type 11, code 0)\n");
            return;
        }

        /* Find out which entry in the routing table has the longest prefix match with the destination IP address.*/
        char *iface_name = find_longest_prefix_name(sr, packet_ip->ip_dst);
        if (iface_name == NULL) {

            /* build icmp echo response */
            send_ICMP_msg(sr, packet, len, interface, 3, 0, iface);
            fprintf(stdout, "Destination net unreachable (type 3, code 0)\n");
            return;
        }
        struct sr_if *itface = sr_get_interface(sr, iface_name);

        struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), ntohl(packet_ip->ip_dst));

        /*Check the ARP cache for the next-hop MAC address corresponding to the next-hop IP. If it’s there, send it*/
        if (entry) {
            memcpy(packet_eth->ether_dhost, entry->mac, ETHER_ADDR_LEN);
            memcpy(packet_eth->ether_shost, itface->addr, ETHER_ADDR_LEN);
            sr_send_packet(sr, packet, len, iface_name);
            free(entry);

        /* Otherwise, send an ARP request for the next-hop IP , and add the packet to the queue of packets waiting on this ARP request. */
        } else {
            struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), ntohl(packet_ip->ip_dst), packet, len, iface_name);
            sr_handle_arprequest(sr, req);
        }
    }
}

/* Handle arp packet */
void sr_handle_arp_packet(struct sr_instance *sr,
                          uint8_t *packet/* lent */,
                          unsigned int len,
                          char *interface/* lent */) {
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
    struct sr_if *source_if = sr_get_interface(sr, interface);

    fprintf(stdout, "Handling ARP request!\n");
    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    struct sr_if *target_if = get_interface_through_ip(sr, arp_header->ar_tip);

    /* In the case of an ARP request, you should only send an ARP reply if the target IP address is one of your router’s IP addresses. */
    if (target_if && ntohs(arp_header->ar_op) == arp_op_request) {
        /* build ARP reply */
        unsigned long length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        uint8_t *arp_reply = (uint8_t *)malloc(length);

        /* build ethernet header */
        build_ether_header((sr_ethernet_hdr_t *)arp_reply,
                           (uint8_t *)eth_hdr->ether_shost, source_if->addr, ethertype_arp);

        /* build arp header */
        build_arp_header((sr_arp_hdr_t *)(arp_reply + sizeof(sr_ethernet_hdr_t)),
                         source_if, arp_header, arp_op_reply);

        fprintf(stdout, "sending an ARP reply\n");
        sr_send_packet(sr, arp_reply, length, source_if->name);
        free(arp_reply);

    /*  In the case of an ARP reply, you should only cache the entry if the target IP address is one of your router’s IP addresses. */
    } else if (target_if && ntohs(arp_header->ar_op) == arp_op_reply) {
        struct sr_arpreq *arpreq = sr_arpcache_insert(&(sr->cache),
                                                      arp_header->ar_sha, ntohl(arp_header->ar_sip));
        if (arpreq) {
            struct sr_packet *packet_pointer = arpreq->packets;
            for (;packet_pointer != NULL; packet_pointer=packet_pointer->next) {
                build_ether_header((sr_ethernet_hdr_t *)packet_pointer->buf,
                                   arp_header->ar_sha, source_if->addr, ethertype(packet_pointer->buf));
                sr_send_packet(sr, packet_pointer->buf, packet_pointer->len, packet_pointer->iface);
            }
            sr_arpreq_destroy(&(sr->cache), arpreq);
        }
    }
}

struct sr_if *get_interface_through_ip(struct sr_instance *sr, uint32_t dest_addr) {
    struct sr_if *pos = sr->if_list;
    for (; pos != NULL; pos = pos->next) {
        if (dest_addr == pos->ip) return pos;
    }
    return NULL;
}

struct sr_rt *find_longest_prefix_match(struct sr_instance *sr, uint32_t dest_addr) {
    struct sr_rt *longest_match = NULL;
    uint32_t longest_int = 0;
    struct sr_rt *r_table = sr->routing_table;

    for (; r_table != NULL; r_table = r_table->next) {
        uint32_t d1 = ntohl(dest_addr) & r_table->mask.s_addr;
        if (ntohl(r_table->gw.s_addr) == d1) {
            if(r_table->mask.s_addr > longest_int) {
                longest_match = r_table;
                longest_int = r_table->mask.s_addr;
            }
        }
    }
    return longest_match;
}


char *find_longest_prefix_name(struct sr_instance *sr, uint32_t dest_addr) {
    struct sr_rt *res = find_longest_prefix_match(sr, dest_addr);
    if (res) {
        return res->interface;
    }
    return NULL;
}

void build_ether_header(sr_ethernet_hdr_t *icmp_msg_eth, uint8_t *dhost, uint8_t *shost, uint16_t type) {
    memcpy(icmp_msg_eth->ether_dhost, dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    memcpy(icmp_msg_eth->ether_shost, shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
    icmp_msg_eth->ether_type = htons(type);
}

void build_ip_header(sr_ip_hdr_t *icmp_msg_ip, uint16_t ip_len, uint32_t src, uint32_t dst, uint8_t ip_p) {
    icmp_msg_ip->ip_len = ip_len;
    icmp_msg_ip->ip_src = src;
    icmp_msg_ip->ip_dst = dst;
    icmp_msg_ip->ip_ttl = ip_p == 3 ? icmp_msg_ip->ip_ttl : INIT_TTL;
    icmp_msg_ip->ip_p = ip_p;
    icmp_msg_ip->ip_sum = 0;
    icmp_msg_ip->ip_sum = cksum(icmp_msg_ip, sizeof(sr_ip_hdr_t));
}

void build_icmp_header(sr_icmp_t3_hdr_t *icmp_msg_icmp, uint8_t type, uint8_t code, int len) {
    icmp_msg_icmp->icmp_type = type;
    icmp_msg_icmp->icmp_code = code;
    icmp_msg_icmp->icmp_sum = 0;
    icmp_msg_icmp->unused = 0;
    icmp_msg_icmp->next_mtu = 0;
    icmp_msg_icmp->icmp_sum = cksum(icmp_msg_icmp, len);
}

void build_arp_header(sr_arp_hdr_t *arp_header, struct sr_if* interface,
                      sr_arp_hdr_t *arp_hdr, unsigned short type) {
    memcpy(arp_header, arp_hdr, sizeof(sr_arp_hdr_t));
    arp_header->ar_op = htons(type);
    /* scource */
    memcpy(arp_header->ar_sha, interface->addr, ETHER_ADDR_LEN);
    arp_header->ar_sip = interface->ip;
    /* destination*/
    memcpy(arp_header->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
    arp_header->ar_tip = arp_hdr->ar_sip;
}

void send_ICMP_msg(struct sr_instance *sr,
                   uint8_t *packet,
                   unsigned int len,
                   char *interface,
                   uint8_t type, uint8_t code, struct sr_if *iface) {
    sr_ethernet_hdr_t *packet_eth = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *packet_ip = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint8_t *reply = NULL;
    unsigned long new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    reply = (uint8_t *)malloc(new_len);
    /* construct ethernet header */
    build_ether_header((sr_ethernet_hdr_t *)reply, packet_eth->ether_shost, iface->addr, ethertype_ip);;
    /* construct ip header */
    uint8_t *reply_ip_buf = reply + sizeof(sr_ethernet_hdr_t);
    memcpy(reply_ip_buf, packet_ip, sizeof(sr_ip_hdr_t));
    build_ip_header((sr_ip_hdr_t *) reply_ip_buf, htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t)),
                    iface->ip, packet_ip->ip_src, ip_protocol_icmp);
    /* construct icmp header */
    sr_icmp_t3_hdr_t *reply_icmp_hdr = (sr_icmp_t3_hdr_t *)(reply_ip_buf + sizeof(sr_ip_hdr_t));
    memcpy(reply_icmp_hdr->data, packet_ip, ICMP_DATA_SIZE);
    build_icmp_header(reply_icmp_hdr, type, code, sizeof(sr_icmp_t3_hdr_t));

    sr_send_packet(sr, reply, new_len, iface->name);
    free(reply);
}