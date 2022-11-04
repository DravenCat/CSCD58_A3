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
uint8_t* construct_icmp_header(uint8_t *ip_buf, struct sr_if* source_if, uint8_t type, uint8_t code, unsigned long total_len);
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

  /* sanity check */
  int success = sanity_check(packet, len);
  if (success != 0) {
    fprintf(stderr, "Failed to handle packet\n");
    return;
  }

  /* get the ethernet header */
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)packet;
  uint16_t ethtype = ethertype(packet);
  struct sr_if *source_if = sr_get_interface(sr, interface);
  
  /* case1: is an arp request */
  if (ethtype == ethertype_arp) {
    fprintf(stdout, "It's a ARP request!\n");
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    struct sr_if *target_if = get_interface_by_ip(sr, arp_hdr->ar_tip);

    /* case1.1: the ARP request destinates to an router interface
     * In the case of an ARP request, you should only send an ARP reply if the target IP address is one of
     * your router's IP addresses */
    if (target_if && ntohs(arp_hdr->ar_op) == arp_op_request) {
      fprintf(stdout, "---------case1.1: arp_request ----------\n");
      /* construct ARP reply */
      unsigned long reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
      uint8_t *arp_reply = (uint8_t *)malloc(reply_len);
      
      /* construct ethernet header */
      construct_eth_header(arp_reply, ehdr->ether_shost, source_if->addr, ethertype_arp);

      /* construct arp header */
      construct_arp_header(arp_reply + sizeof(sr_ethernet_hdr_t), source_if, arp_hdr, arp_op_reply);

      fprintf(stdout, "sending ARP reply packet\n");
      sr_send_packet(sr, arp_reply, reply_len, source_if->name);
      free(arp_reply);
    }
    /* case1.2: the ARP reply destinates to an router interface
     * In the case of an ARP reply, you should only cache the entry if the target IP
     * address is one of your router's IP addresses. */
    else if (target_if && ntohs(arp_hdr->ar_op) == arp_op_reply) {
      fprintf(stdout, "---------case1.2: arp_response ----------\n");
      struct sr_arpreq *arpreq = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, ntohl(arp_hdr->ar_sip));
      if (arpreq) {
        struct sr_packet *pkt;
        for (pkt=arpreq->packets; pkt != NULL; pkt=pkt->next) {
          construct_eth_header(pkt->buf, arp_hdr->ar_sha, source_if->addr, ethertype(pkt->buf));
          sr_send_packet(sr, pkt->buf, pkt->len, pkt->iface);
        }
        sr_arpreq_destroy(&(sr->cache), arpreq);
      }
    }
  }

  /* case2: is an ip request */
  else if (ethtype == ethertype_ip) {
    uint8_t *ip_buf = packet+sizeof(sr_ethernet_hdr_t);
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)ip_buf;
    struct sr_if *target_if = get_interface_by_ip(sr, ip_hdr->ip_dst);
    fprintf(stdout, "It's TTL is: %d\n", ip_hdr->ip_ttl);

    int success = handle_chksum(ip_hdr);
    if (success == -1) {
      fprintf(stderr, "IP header chsum failed!\n");
      return;
    }
    /* If it is sent to one of your router's IP addresses, */
    /* case2.1: the request destinates to an router interface */
    if (target_if) {
      fprintf(stderr, "---------case2.1: to router ----------\n");
      /* If the packet is an ICMP echo request and its checksum is valid, 
       * send an ICMP echo reply to the sending host. */
      int protocol = ip_protocol(packet+sizeof(sr_ethernet_hdr_t));
      if (protocol == ip_protocol_icmp) {
        fprintf(stderr, "---------case2.1.1: icmp ----------\n");
        /* construct ethernet header */
        construct_eth_header(packet, ehdr->ether_shost, source_if->addr, ethertype_ip);
        /* construct ip header */
        construct_ip_header(ip_buf, ip_hdr->ip_src, ip_hdr->ip_dst, ip_protocol_icmp);
        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
        if (icmp_hdr->icmp_type == (uint8_t)8) {
          fprintf(stderr, "sending an ICMP echo response\n");
          uint16_t sum = icmp_hdr->icmp_sum;
          icmp_hdr->icmp_sum = 0;
          icmp_hdr->icmp_sum = cksum(icmp_hdr, len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
          if (sum != icmp_hdr->icmp_sum) {
            fprintf(stderr, "Incorrect checksum\n");
            return;
          }
         
          /* construct icmp echo response */
          construct_icmp_header(packet, source_if, 0, 0, len);
          fprintf(stdout, "sending ICMP (type:0, code:0)\n");
          sr_send_packet(sr, packet, len, source_if->name);
        }
      }
      /* If the packet contains a TCP or UDP payload, send an 
      * ICMP port unreachable to the sending host. */
      else if (protocol == ip_protocol_tcp || protocol == ip_protocol_udp) {
        fprintf(stderr, "---------case2.1.2: tcp/udp ----------\n");
        /* construct icmp echo response */
        uint8_t *reply = construct_icmp_header(packet, source_if, 3, 3, len);
        unsigned long new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

        fprintf(stdout, "sending ICMP (Type 3, Code 3) unreachable\n");
        sr_send_packet(sr, reply, new_len, source_if->name);
        free(reply);
      }
    }
    /* case2.2: the request does not destinate to an router interface */
    else {
      fprintf(stderr, "---------case2.2: to other place----------\n");
      /* decrement TTL by 1 */
      ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
      ip_hdr->ip_sum = 0;
      ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

      /* Sent ICMP type 11 code 0, if an IP packet is discarded during processing because the TTL field is 0 */
      if (ip_hdr->ip_ttl < 0) {
         /* construct icmp echo response */
        uint8_t *reply = construct_icmp_header(packet, source_if, 11, 0, len);
        unsigned long new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        fprintf(stdout, "sending ICMP (Type 11, Code 0) unreachable\n");
        sr_send_packet(sr, reply, new_len, source_if->name);
        free(reply);
        return;
      }

      /* Find out which entry in the routing table has the longest prefix match 
         with the destination IP address. */
      char *oif_name = get_interface_by_LPM(sr, ip_hdr->ip_dst);
      if (oif_name == NULL) {
   
        /* construct icmp echo response */
        uint8_t *reply = construct_icmp_header(packet, source_if, 3, 0, len);
        unsigned long new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
        fprintf(stdout, "sending ICMP (Type 3, Code 0) unreachable\n");
        sr_send_packet(sr, reply, new_len, source_if->name);
        free(reply);
        return;
      }
      struct sr_if *oif = sr_get_interface(sr, oif_name);

      /* send packet to next_hop_ip */
      struct sr_arpentry *entry = sr_arpcache_lookup(&(sr->cache), ntohl(ip_hdr->ip_dst));
      if (entry) {
        /* use next_hop_ip->mac mapping in entry to send the packet*/
        memcpy(ehdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        memcpy(ehdr->ether_shost, oif->addr, ETHER_ADDR_LEN);
        sr_send_packet(sr, packet, len, oif_name);
        free(entry);
      }
      else {
        struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), ntohl(ip_hdr->ip_dst), packet, len, oif_name);
        handle_arpreq(sr, req);
      }
    }
  }

}/* end sr_ForwardPacket */

void construct_eth_header(uint8_t *buf, uint8_t *dst, uint8_t *src, uint16_t type) {
  sr_ethernet_hdr_t *reply_ehdr = (sr_ethernet_hdr_t *)buf;
  memcpy(reply_ehdr->ether_dhost, dst, ETHER_ADDR_LEN);
  memcpy(reply_ehdr->ether_shost, src, ETHER_ADDR_LEN);
  reply_ehdr->ether_type = htons(type);
}

void construct_arp_header(uint8_t *buf, struct sr_if* source_if, sr_arp_hdr_t *arp_hdr, unsigned short type) {
  sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)buf;
  memcpy(reply_arp_hdr, arp_hdr, sizeof(sr_arp_hdr_t));
  reply_arp_hdr->ar_op = htons(type);
  /* scource */
  memcpy(reply_arp_hdr->ar_sha, source_if->addr, ETHER_ADDR_LEN);
  reply_arp_hdr->ar_sip = source_if->ip;
  /* destination*/
  memcpy(reply_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  reply_arp_hdr->ar_tip = arp_hdr->ar_sip;
}

void construct_ip_header(uint8_t *buf, uint32_t dst, uint32_t src, uint16_t type) {
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buf);
  ip_hdr->ip_src = src;
  ip_hdr->ip_dst = dst;
  ip_hdr->ip_p = type;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
}

uint8_t* construct_icmp_header(uint8_t *buf, struct sr_if* source_if, uint8_t type, uint8_t code, unsigned long total_len) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
  uint8_t *reply = NULL;
  
  if (type == 0) {
    sr_icmp_hdr_t *reply_icmp_hdr = (sr_icmp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    reply_icmp_hdr->icmp_type = type;
    reply_icmp_hdr->icmp_code = code;
    reply_icmp_hdr->icmp_sum = 0;
    reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, total_len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
    reply = buf;
  }
  else if (type == 3 || type == 11) {
    unsigned long new_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    reply = (uint8_t *)malloc(new_len);
    /* construct ethernet header */
    construct_eth_header(reply, ehdr->ether_shost, source_if->addr, ethertype_ip);
    /* construct ip header */
    uint8_t *reply_ip_buf = reply + sizeof(sr_ethernet_hdr_t);
    memcpy(reply_ip_buf, ip_hdr, sizeof(sr_ip_hdr_t));
    sr_ip_hdr_t *reply_ip = (sr_ip_hdr_t *) reply_ip_buf;
    reply_ip->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
    if (type == 11) {
      reply_ip->ip_ttl = 100;
    }
    construct_ip_header(reply_ip_buf, ip_hdr->ip_src, source_if->ip, ip_protocol_icmp);
    /* construct icmp header */
    sr_icmp_t3_hdr_t *reply_icmp_hdr = (sr_icmp_t3_hdr_t *)(reply_ip_buf + sizeof(sr_ip_hdr_t));
    reply_icmp_hdr->icmp_type = type;
    reply_icmp_hdr->icmp_code = code;
    reply_icmp_hdr->icmp_sum = 0;
    reply_icmp_hdr->unused = 0;
    reply_icmp_hdr->next_mtu = 0;
    memcpy(reply_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
    reply_icmp_hdr->icmp_sum = cksum(reply_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
  }
  return reply;
}

/* Get interface name by longest prefix match */
char* get_interface_by_LPM(struct sr_instance* sr, uint32_t ip_dst) {
  struct sr_rt *entry = sr->routing_table;
  struct sr_rt *match = NULL;
  int longest_mask = 0;
  while (entry) {
    uint32_t netid = ntohl(ip_dst) & entry->mask.s_addr;
    if (ntohl(entry->gw.s_addr) == netid) {
      if (longest_mask < entry->mask.s_addr) {
        longest_mask = entry->mask.s_addr;
        match = entry;
      }
    }
    entry = entry->next;
  }
  return match != NULL ? match->interface : NULL;
}

/* Get interface object by exact match */
struct sr_if* get_interface_by_ip(struct sr_instance* sr, uint32_t tip) {
  struct sr_if *if_walker = sr->if_list;
  while (if_walker) {
    if (if_walker->ip == tip) {
      return if_walker;
    }
    if_walker = if_walker->next;
  }
  return 0;
}

int handle_chksum(sr_ip_hdr_t *ip_hdr) {
  /* inspect checksum */
  uint16_t sum = ip_hdr->ip_sum;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
  if (sum != ip_hdr->ip_sum) {
    fprintf(stderr, "Incorrect checksum\n");
    return -1;
  }
  return 0;
}

int sanity_check(uint8_t *buf, unsigned int length) {
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    return -1;
  }
  uint16_t ethtype = ethertype(buf);
  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      return -1;
    }

    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));
    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        return -1;
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      return -1;
  }
  else {
    return -1;
  }
  return 0;
}