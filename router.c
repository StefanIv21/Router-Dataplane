#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "list.h"
#include <arpa/inet.h>
#include <string.h>


struct route_table_entry * rtable;
int rtable_len;

struct arp_entry * arp_table;
int arp_table_len;
int arp_capacity;

queue q;

//structura pentru a retine datele unui packet in coada
typedef struct {
  int len;
  char buf[MAX_PACKET_LEN];
  int interface;
  uint32_t route;
}
packet;

//cautare binara in tabela de rutare
//daca am gasit o potrivire caut cea mai mare masca 
struct route_table_entry * get_best_route(uint32_t dest_ip) {
  struct route_table_entry *entry;
  int low = 0, high = rtable_len - 1;
  int mid;

  while (low <= high) {
    mid = low + (high - low) / 2;
    if (rtable[mid].prefix == (dest_ip & rtable[mid].mask)) {
      entry = &rtable[mid];
      while (1) {
        mid--;
        if (rtable[mid].prefix > (dest_ip & rtable[mid].mask))
        {
          return entry ;
        }
        if(rtable[mid].mask >= entry->mask)
          entry = &rtable[mid];  
      }
    }
    if (rtable[mid].prefix > (dest_ip & rtable[mid].mask)) {
      low = mid + 1;
    } else high = mid - 1;
  }
  return NULL;
}
//functie de comparare pt qsort(sorteaza dupa prefix si apoi dupa masca)
int compare(const void * a,
  const void * b) {

  struct route_table_entry * a1 = (struct route_table_entry * ) a;
  struct route_table_entry * a2 = (struct route_table_entry * ) b;

  int dif = a2 -> prefix - a1 -> prefix;
  if (a1 -> prefix == a2 -> prefix) {
    return a2-> mask - a1 -> mask;
  }
  return dif;
}

//functie pentru a extrage mac ul in functie de ip
struct arp_entry * get_arp_entry(uint32_t dest_ip) {

  for (int i = 0; i < arp_capacity; i++) {
    if (arp_table[i].ip == dest_ip)
      return & arp_table[i];
  }
  return NULL;

}

int main(int argc, char * argv[]) {
  char buf[MAX_PACKET_LEN];

  // Do not modify this line
  init(argc - 2, argv + 2);

  //Alocare de memorie pentru tabele de rutare si pentru tabela ARP
  rtable = malloc(sizeof(struct route_table_entry) * 100000);
  rtable_len = read_rtable(argv[1], rtable);

  arp_table_len = 10;
  arp_table = malloc(sizeof(struct arp_entry) * arp_table_len);
  arp_capacity = 0;

  qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare);

  //Creez coada de pachete
  q = queue_create();

  while (1) {

    int interface;
    size_t len;

    interface = recv_from_any_link(buf, & len);
    DIE(interface < 0, "recv_from_any_links");

    struct ether_header * eth_hdr = (struct ether_header * ) buf;
    /* Note that packets received are in network order,
    any header field which has more than 1 byte will need to be conerted to
    host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
    sending a packet on the link, */

    //Verific de ce tip este mesajul (IP SAU ARP)
    if (ntohs(eth_hdr -> ether_type) == 0x0800) {

      struct iphdr * ip_hdr = (struct iphdr * )(buf + sizeof(struct ether_header));

      //Daca pachetul este pentru router si este de tip request, trimit un IMCP reply
      if (ip_hdr -> daddr == inet_addr(get_interface_ip(interface))) {
        struct icmphdr * icmp_hdr = (struct icmphdr * )(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
        if (icmp_hdr -> type == 8) {

          len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

          char buf2[MAX_PACKET_LEN];
          memcpy(buf2, buf, MAX_PACKET_LEN);

          struct ether_header * eth_hdr2 = (struct ether_header * ) buf2;
          struct iphdr * ip_hdr2 = (struct iphdr * )(eth_hdr2 + sizeof(struct ether_header));
          struct icmphdr * icmp_hdr2 = (struct icmphdr * )(buf2 + sizeof(struct ether_header) + sizeof(struct iphdr));

          memcpy(eth_hdr2 -> ether_dhost, eth_hdr -> ether_shost, 6);
          memcpy(eth_hdr2 -> ether_shost, eth_hdr -> ether_dhost, 6);
          eth_hdr2 -> ether_type = eth_hdr -> ether_type;

          ip_hdr2 -> daddr =ip_hdr->saddr;
          ip_hdr2 -> saddr =ip_hdr->daddr;
        

          ip_hdr2 -> ttl = 64;
          ip_hdr2 -> tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

          icmp_hdr2 -> type = 0;
          icmp_hdr2 -> checksum = 0;
          icmp_hdr2 -> checksum = checksum((uint16_t * ) icmp_hdr2, sizeof(struct icmphdr));

          send_to_link(interface, buf2, len);
          continue;
        }

      }
      //Vefirifc checksumul pachetului (dau drop daca este diferit)
      uint16_t old = ip_hdr -> check;
      ip_hdr -> check = 0;
      uint16_t new = checksum((uint16_t * ) ip_hdr, sizeof(struct iphdr));
      ip_hdr -> check = htons(new);

      if (old != ip_hdr -> check) {
        continue;
      }

      //Daca ttl este mai mic sau egal cu 1 trimit un ICMP reply corespunzator
      if (ip_hdr -> ttl <= 1) {

        len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

        char buf2[MAX_PACKET_LEN];
        memcpy(buf2, buf, MAX_PACKET_LEN);

        struct ether_header * eth_hdr2 = (struct ether_header * ) buf2;
        struct iphdr * ip_hdr2 = (struct iphdr * )(buf2 + sizeof(struct ether_header));
        struct icmphdr * icmp_hdr2 = (struct icmphdr * )(buf2 + sizeof(struct ether_header) + sizeof(struct iphdr));

        memcpy(eth_hdr2 -> ether_dhost, eth_hdr -> ether_shost, 6);
        memcpy(eth_hdr2 -> ether_shost, eth_hdr -> ether_dhost, 6);
        eth_hdr2 -> ether_type = eth_hdr -> ether_type;

        ip_hdr2 -> daddr =ip_hdr->saddr;
        ip_hdr2 -> saddr =ip_hdr->daddr;

        ip_hdr2 -> protocol = 1;
        ip_hdr2 -> ttl = 64;
        ip_hdr2 -> tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

        icmp_hdr2 -> type = 11;

        icmp_hdr2 -> checksum = 0;
        icmp_hdr2 -> checksum = checksum((uint16_t * ) icmp_hdr2, sizeof(struct icmphdr));

        send_to_link(interface, buf2, len);
        continue;

      }

      //Caut adresa pentru urmatorul hop 
      //Daca nu s a gasit ,returnez un reply ICMP corespunzator
      struct route_table_entry * route = get_best_route(ip_hdr -> daddr);

      if (route == NULL) {
        len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

        char buf2[MAX_PACKET_LEN];
        memcpy(buf2, buf, MAX_PACKET_LEN);

        struct ether_header * eth_hdr2 = (struct ether_header * ) buf2;
        struct iphdr * ip_hdr2 = (struct iphdr * )(buf2 + sizeof(struct ether_header));
        struct icmphdr * icmp_hdr2 = (struct icmphdr * )(buf2 + sizeof(struct ether_header) + sizeof(struct iphdr));

        memcpy(eth_hdr2 -> ether_dhost, eth_hdr -> ether_shost, 6);
        memcpy(eth_hdr2 -> ether_shost, eth_hdr -> ether_dhost, 6);
        eth_hdr2 -> ether_type = eth_hdr -> ether_type;

        ip_hdr2 -> daddr = ip_hdr-> saddr;
        ip_hdr2 -> saddr = ip_hdr-> daddr;
        

        ip_hdr2 -> protocol = 1;
        ip_hdr2 -> ttl = 64;
        ip_hdr2 -> tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

        icmp_hdr2 -> type = 3;
        icmp_hdr2 -> checksum = 0;
        icmp_hdr2 -> checksum = checksum((uint16_t * ) icmp_hdr2, sizeof(struct icmphdr));

        send_to_link(interface, buf2, len);
        continue;
      }

      //scad ttl si actualizez checksumul nou
      ip_hdr -> ttl--;
      ip_hdr -> check = 0;
      ip_hdr -> check = checksum((uint16_t * ) ip_hdr, sizeof(struct iphdr));
      ip_hdr -> check = htons(ip_hdr -> check);

      //caut adresa mac pt hop ul urmator
      //daca nu exista in tabela ARP, creez un ARP request

      struct arp_entry * arp = get_arp_entry(route -> next_hop);
      if (arp == NULL) {

        //pun pachetul in coada 
        packet * p = (packet * ) malloc(sizeof(packet));
        p -> interface = route -> interface;
        p -> len = len;
        p -> route = route -> next_hop;
        memcpy(p -> buf, & buf, MAX_PACKET_LEN * sizeof(char));
        queue_enq(q, p);

        len = sizeof(struct ether_header) + sizeof(struct arp_header);

        char buf2[MAX_PACKET_LEN];

        struct ether_header * eth_header = (struct ether_header * ) malloc(sizeof(struct ether_header));

        uint8_t broadcast[6] = {
          0xff,
          0xff,
          0xff,
          0xff,
          0xff,
          0xff
        };

        memcpy(eth_header -> ether_dhost, broadcast, 6);

        get_interface_mac(route -> interface, eth_header -> ether_shost);

        eth_header -> ether_type = htons(0x0806);

        struct arp_header * arp_hdr = (struct arp_header * ) malloc(sizeof(struct arp_header));
        arp_hdr -> htype = htons(1);
        arp_hdr -> ptype = htons(0x0800);
        arp_hdr -> hlen = 6;
        arp_hdr -> plen = 4;
        arp_hdr -> op = htons(1);

        get_interface_mac(route -> interface, arp_hdr -> sha);
        arp_hdr -> spa = inet_addr(get_interface_ip(route -> interface));

        memcpy(arp_hdr -> tha, broadcast, 6);
        arp_hdr -> tpa = route -> next_hop;

        memset(buf2, 0, MAX_PACKET_LEN);

        memcpy(buf2, eth_header, sizeof(struct ether_header));
        memcpy(buf2 + sizeof(struct ether_header), arp_hdr,
          sizeof(struct arp_header));

        send_to_link(route -> interface, buf2, len);
        continue;
      }

      //daca exista adresa mac pt umrator hop ,actualizez ethernet header ul si interfata
      memcpy(eth_hdr -> ether_dhost, arp -> mac, 6);
      get_interface_mac( interface, eth_hdr -> ether_shost);
      send_to_link(route -> interface, buf, len);

    }

    //Verific de ce tip este mesajul (IP SAU ARP)
    if (ntohs(eth_hdr -> ether_type) == 0x0806) {

      struct ether_header * eth = (struct ether_header * ) buf;

      struct arp_header * arp_hdr = ((void * ) eth) + sizeof(struct ether_header);

      //daca pachetul este de tip reply
      //copiez adresa ip si mac in ARP table
      if (ntohs(arp_hdr -> op) == 2)

      {

        //daca pachetul nu este pentru noi ii dau drop
        if (arp_hdr -> tpa != inet_addr(get_interface_ip(interface)))
          continue;

        arp_table[arp_capacity].ip = arp_hdr -> spa;
        memcpy(arp_table[arp_capacity].mac, arp_hdr -> sha, 6);
        arp_capacity++;

        if (arp_capacity == arp_table_len) {
          arp_table_len *= 2;
          arp_table = realloc(arp_table, arp_table_len);

        }

        //cat timp am pachete in coada,le scot si le trmit pe hop ul urmator
        //daca exista un pachet care nu are inca adresa mac in tabela ARP,il readaug in coada si ma opresc
        while (!queue_empty(q)) {

          packet * p = (packet * ) malloc(sizeof(packet));
          p = (packet * ) queue_deq(q);

          struct ether_header * packet_eth = (struct ether_header * ) p -> buf;

          struct arp_entry * arp = get_arp_entry(p -> route);

          if (arp == NULL) {
            queue_enq(q, p);
            break;
          }

          memcpy(packet_eth -> ether_dhost, arp -> mac, 6);

          send_to_link(p -> interface, p -> buf, p -> len);
          free(p);

        }
        continue;

      }

      //daca pachetul este de tip request si este pentru router
      //creez un arp reply cu mac ul adresei dorite si il trimit inapoi
      if (ntohs(arp_hdr -> op) == 1) {

        if (arp_hdr -> tpa != inet_addr(get_interface_ip(interface)))
          continue;

        len = sizeof(struct ether_header) + sizeof(struct arp_header);
        char buf2[MAX_PACKET_LEN];
        memcpy(buf2, buf, MAX_PACKET_LEN);

        struct ether_header * eth_hdr2 = (struct ether_header * ) buf2;
        struct arp_header * arph_reply = (struct arp_header * )(buf2 + sizeof(struct ether_header));

        arph_reply -> op = htons(2);
        arph_reply -> spa = arp_hdr -> tpa;
        arph_reply -> tpa = arp_hdr -> spa;

      
        memcpy(arph_reply -> tha, arp_hdr -> sha, 6);

        get_interface_mac(interface, arph_reply -> sha);

        memcpy(eth_hdr2 -> ether_dhost, eth_hdr -> ether_shost, 6);

        get_interface_mac(interface, eth_hdr2 -> ether_shost);

        send_to_link(interface, buf2, len);
        continue;
      }

    }

  }
}