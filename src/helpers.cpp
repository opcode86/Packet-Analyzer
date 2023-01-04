#include <iostream>
#include <pcap.h>
#include <pcap/pcap.h>
#include <sys/types.h>

#include "helpers.h"

uint32_t packet::ipv4(const u_char *packet, const u_char *length,
                      int &start) noexcept {
  printf("\n\nProtocol: IPV4\nHeader:\n");
  struct _ip4hdr *hdr = (struct _ip4hdr *)(length);

  for (int i = start; i < start + sizeof(struct _ip4hdr); i++) {
    printf("%02x ", packet[i]);
  }

  printf("\nSource: %d.%d.%d.%d\n", hdr->saddr[0], hdr->saddr[1], hdr->saddr[2],
         hdr->saddr[3]);
  printf("Destination: %d.%d.%d.%d\n", hdr->daddr[0], hdr->daddr[1],
         hdr->daddr[2], hdr->daddr[3]);
  printf("TTL: %d", hdr->ttl);

  start += sizeof(struct _ip4hdr);

  return hdr->protocol;
}

uint32_t packet::ipv6(const u_char *packet, const u_char *length,
                      int &start) noexcept {
  printf("\n\nProtocol: IPV6\nHeader:\n");

  struct _ip6hdr *hdr = (struct _ip6hdr *)(length);

  for (int i = start; i < start + sizeof(struct _ip6hdr); i++) {
    printf("%02x ", packet[i]);
  }

  printf("\nSource: %02x:%02x:%02x:%02x\n", hdr->source[0], hdr->source[1],
         hdr->source[2], hdr->source[3]);
  printf("Destination: %02x:%02x:%02x:%02x\n", hdr->destination[0],
         hdr->destination[1], hdr->destination[2], hdr->destination[3]);
  printf("TTL: %d\n", hdr->limit);

  start += sizeof(struct _ip6hdr);

  return hdr->next;
}

uint32_t packet::arp(const u_char *packet, const u_char *length,
                     int &start) noexcept {
  printf("\n\nProtocol: ARP\nHeader:\n");

  struct _arphdr *hdr = (struct _arphdr *)(length);

  for (int i = start; i < start + sizeof(struct _arphdr); i++) {
    printf("%02x ", packet[i]);
  }

  printf("\n\nSender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", hdr->sha[0],
         hdr->sha[1], hdr->sha[2], hdr->sha[3], hdr->sha[4], hdr->sha[5]);
  printf("Sender protocol address: %d.%d.%d.%d\n\n", hdr->spa[0], hdr->spa[1],
         hdr->spa[2], hdr->spa[3]);
  printf("Target MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", hdr->tha[0],
         hdr->tha[1], hdr->tha[2], hdr->tha[3], hdr->tha[4], hdr->tha[5]);
  printf("Target protocol address: %d.%d.%d.%d\n", hdr->tpa[0], hdr->tpa[1],
         hdr->tpa[2], hdr->tpa[3]);

  return 0;
}

uint32_t packet::tcp(const u_char *packet, const u_char *length,
                     int &start) noexcept {
  printf("\n\nProtocol: TCP\nHeader:\n");

  struct _tcphdr *hdr = (struct _tcphdr *)(length);

  for (int i = start; i < start + sizeof(struct _tcphdr); i++) {
    printf("%02x ", packet[i]);
  }

  printf("\n\nTCP segment length: %d\nSource port: %d\nDestination port: %d\n",
         ntohs(hdr->offset), ntohs(hdr->source_port),
         ntohs(hdr->desination_port));

  start += sizeof(struct _tcphdr);

  return ntohs(hdr->offset);
}

uint32_t packet::udp(const u_char *packet, const u_char *length,
                     int &start) noexcept {
  printf("\n\nProtocol: UDP\nHeader:\n");

  struct _udphdr *hdr = (struct _udphdr *)(length);

  for (int i = start; i < start + sizeof(struct _udphdr); i++) {
    printf("%02x ", packet[i]);
  }

  printf("\n\nUDP segment length: %d\nSource port: %d\nDestination port: %d\n",
         ntohs(hdr->length), ntohs(hdr->source_port),
         ntohs(hdr->desination_port));

  start += sizeof(struct _udphdr);

  return ntohs(hdr->length); // temp
}