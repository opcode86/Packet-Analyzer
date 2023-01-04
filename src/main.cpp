#include <cstdint>
#define ADDRESS_IPV4 2
#define ADDRESS_IPV6 23

#define TYPE_TCP 0x06
#define TYPE_UDP 0x11

#define TYPE_LLC 0x56

#define TYPE_IPV4 0x800
#define TYPE_ARP 0x806
#define TYPE_IPV6 0x86DD

#define PORT_NBNS 0x89 // NETBIOS

#define PACKET_COUNT 5

#ifdef _WIN32
#define DEVICE "REDACTED"
#elif __linux__
#define DEVICE "wlan0"
#include <arpa/inet.h>
#include <netinet/in.h>
#define HAVE_REMOTE
#endif

#include <iostream>
#include <pcap.h>
#include <pcap/pcap.h>

#ifdef _WIN32
#include <InetSDK.h>
#pragma comment(lib, "Packet.lib")
#pragma comment(lib, "wpcap.lib")

#elif __linux__ // g++ src/*.cpp -o "main" -lpcap
#include <net/ethernet.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>

#endif

#include "helpers.h"

int packetCount = 0;

void dumpData(pcap_if_t *allDevices, int &deviceCount) noexcept {
  pcap_if_t *device;
  for (device = allDevices; device != NULL;
       device = device->next, deviceCount++) {
    if (device->name == NULL) [[unlikely]]
      continue;

    printf("\n\nName: %s. Description: %s. \nAddresses:\n", device->name,
           device->description);

    pcap_addr_t *addr;
    for (addr = device->addresses; addr != NULL; addr = addr->next) {

      printf("\n--] ");
      for (auto x : addr->addr->sa_data) {
        printf("%02x:", x);
      }
    }
  }
}

void packetCallback2(u_char *args, const struct pcap_pkthdr *hdr,
                     const u_char *packet) noexcept {

  int next = 0;
  auto packetNew = packet;
  struct _ethhdr *eth = (struct _ethhdr *)packet;

  int offset = sizeof(struct _ethhdr);
  auto length = packet + sizeof(struct _ethhdr);

  printf("\n\nRaw packet data in hex:\n");
  for (int i = 0; i < hdr->len; i++) {
    printf("%02x ", packet[i]);
  }

  switch (ntohs(eth->h_proto)) {
    [[likely]] case TYPE_IPV4 : next = packet::ipv4(packet, length, offset);
    length += sizeof(struct _ip4hdr);
    break;
  case TYPE_IPV6:
    next = packet::ipv6(packet, length, offset);
    length += sizeof(struct _ip6hdr);
    break;
  case TYPE_ARP:
    next = packet::arp(packet, length, offset);
    length += sizeof(struct _arphdr);
    break;
  default:
    return;
  }

  switch (next) {
  case TYPE_TCP:
    next = packet::tcp(packet, length, offset);
    length += sizeof(struct _tcphdr);
    break;
  case TYPE_UDP:
    next = packet::udp(packet, length, offset);
    length += sizeof(struct _udphdr);
    break;
  default:
    return;
  }

  packetCount++;
  if (packetCount >= PACKET_COUNT)
    exit(0);
}

int main(int argc, char *argv[]) {
  char errorBuffer[PCAP_ERRBUF_SIZE];
  pcap_t *handle = nullptr;
  bpf_u_int32 mask;
  bpf_u_int32 net;

  int deviceCount = 0;
  pcap_if_t *allDevices, *device;

  struct bpf_program fp;

  if (pcap_lookupnet(NULL, &mask, &net, errorBuffer) == 1) {
    printf("%s", errorBuffer);
    return 0;
  }

  if (pcap_findalldevs(&allDevices, errorBuffer) == -1) {
    printf("%s", errorBuffer);
    return 0;
  }

  dumpData(allDevices, deviceCount);

  printf("\nDevice count (including NULL): %d\n", deviceCount);

  pcap_freealldevs(allDevices);

  handle = pcap_open_live(DEVICE, BUFSIZ, 1, 1000, errorBuffer);
  if (handle == 0) {
    printf("Failed to open session!\n");
    return 0;
  }

  bpf_u_int32 bpfBuffer = {}; //"ip"
  if (pcap_compile(handle, &fp, NULL, 1, bpfBuffer) == -1) {
    printf("Failed to compile!");
    return 0;
  }

  if (pcap_setfilter(handle, &fp) == -1) {
    printf("Failed to set filter!");
    return 0;
  }

  pcap_loop(handle, -1, packetCallback2, NULL);

  pcap_close(handle);

  return 0;
}