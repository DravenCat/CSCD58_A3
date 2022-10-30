# CSCD58_A3
TODO:

### ARP part

Author: Yuanqian(Richard) Fang

Working file: sr_arpcache.c

void sr_arpcache_sweepreqs(struct sr_instance *sr)

### IP part 

Author: Dezhi(Geralt) Ren 

Working file: sr_router.c 

void sr_handlepacket(struct sr_instance* sr,
   uint8_t * packet,
   unsigned int len,
   char* interface)

### Check destination, hardware address.

Author: Haowen(Anson) Rui 

Working file: sr_vns_comm.c

static int sr_ether_addrs_match_interface(struct sr_instance* sr, 
uint8_t* buf, 
const char* name)