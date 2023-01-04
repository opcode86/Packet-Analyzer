#pragma once
#include <cstdint>
#include <stdint.h>
#include <sys/types.h>

#ifndef ETH_LEN
#define ETH_LEN 6
#endif

#ifdef _WIN32
#define PACK_START __pragma(pack(push, 1))
#define PACK_STOP                                                              \
  ;                                                                            \
  __pragma(pack pop)
#elif __linux__
#define PACK_START
#define PACK_STOP __attribute__((packed, aligned(1)));
#endif

struct _ethhdr {
  unsigned char h_dest[ETH_LEN];   // 6 bytes
  unsigned char h_source[ETH_LEN]; // 6 bytes
  uint16_t h_proto;                // 2 bytes
};

PACK_START
struct _ip4hdr {
  unsigned char version : 4;
  unsigned char ihl : 4;
  // uint8_t tos;
  unsigned char dscp : 6;
  unsigned char ecn : 2;
  uint16_t tot_len;
  uint16_t id;
  uint16_t frag_off;
  uint8_t ttl;
  uint8_t protocol;
  uint16_t check;
  uint8_t saddr[4];
  uint8_t daddr[4];
} PACK_STOP

    PACK_START struct _ip6hdr {
  union {
    unsigned char version : 4;
    uint8_t traffic_class;
    unsigned int flow_label : 20;
    uint32_t reserved;
  };

  uint16_t payload_length;
  uint8_t next;
  uint8_t limit;

  uint32_t source[4];
  uint32_t destination[4];
} PACK_STOP

    PACK_START struct _arphdr {
  uint16_t h_type; // h = hardware
  uint16_t p_type; // p = protocol
  uint8_t h_len;
  uint8_t p_len;
  uint16_t operation;
  uint8_t sha[6];
  uint8_t spa[4];
  uint8_t tha[6];
  uint8_t tpa[4];
} PACK_STOP

    /*
    struct tcphdr
      {
            __extension__ union
            {
                    struct
                    {
                            uint16_t th_sport;	// source port
                            uint16_t th_dport;	// destination port
                            tcp_seq th_seq;		// sequence number
                            tcp_seq th_ack;		// acknowledgement
    number # if __BYTE_ORDER == __LITTLE_ENDIAN uint8_t th_x2:4;	//
    (unused) uint8_t th_off:4;	// data offset # endif # if __BYTE_ORDER ==
    __BIG_ENDIAN uint8_t th_off:4;	// data offset uint8_t th_x2:4;	//
    (unused) # endif uint8_t th_flags; # define TH_FIN	0x01 # define TH_SYN
    0x02 # define TH_RST	0x04 # define TH_PUSH	0x08 # define TH_ACK
    0x10 # define TH_URG	0x20 uint16_t th_win;	// window uint16_t
    th_sum;	// checksum uint16_t th_urp;	// urgent pointer
                    };
                    struct
                    {
                            uint16_t source;
                            uint16_t dest;
                            uint32_t seq;
                            uint32_t ack_seq;
    # if __BYTE_ORDER == __LITTLE_ENDIAN
                            uint16_t res1:4;
                            uint16_t doff:4;
                            uint16_t fin:1;
                            uint16_t syn:1;
                            uint16_t rst:1;
                            uint16_t psh:1;
                            uint16_t ack:1;
                            uint16_t urg:1;
                            uint16_t res2:2;
    # elif __BYTE_ORDER == __BIG_ENDIAN
                            uint16_t doff:4;
                            uint16_t res1:4;
                            uint16_t res2:2;
                            uint16_t urg:1;
                            uint16_t ack:1;
                            uint16_t psh:1;
                            uint16_t rst:1;
                            uint16_t syn:1;
                            uint16_t fin:1;
    # else
    #  error "Adjust your <bits/endian.h> defines"
    # endif
                            uint16_t window;
                            uint16_t check;
                            uint16_t urg_ptr;
                    };
            };
    };
    */

    PACK_START struct _tcphdr {
  uint16_t source_port;
  uint16_t desination_port;

  uint32_t sequence_number;
  uint32_t acknowledge_number;

  unsigned char offset : 4;
  unsigned char reserved : 4; // - 1
  // unsigned char ns : 1;
  unsigned char flags;

  /*
  unsigned int ns : 1;

  unsigned int cwr : 1;
  unsigned int ece : 1;
  unsigned int urg : 1;
  unsigned int ack : 1;
  unsigned int psh : 1;
  unsigned int rst : 1;
  unsigned int syn : 1;
  unsigned int fin : 1;
  */
  uint16_t window_size;

  uint16_t checksum;
  uint16_t urgent_pointer;
} PACK_STOP

    PACK_START struct _tlshdr {
  uint8_t content_type;
  uint16_t versionl;
  uint16_t length;
} PACK_STOP

    struct _udphdr {
  uint16_t source_port;
  uint16_t desination_port;
  uint16_t length;
  uint16_t checksum;
};

PACK_START struct _base_radiotaphdr {
  uint8_t revision : 1;
  uint8_t pad : 1;
  uint8_t length : 2; // length of entire radiotap header
  uint8_t present_flags : 4;
} PACK_STOP

    PACK_START struct _ieeehdr {
  uint8_t mac_timestamp;
  uint8_t flags : 1;
  uint8_t datarate : 1; // Mb/s
  uint8_t channel_frequency : 2;
  uint8_t channel_flags : 2;
  uint8_t antenna_signal : 1; // must be converted to 2s compliment
  uint8_t rx_flags : 2;
  uint16_t timestamp_information : 12;
  uint8_t antenna_signal_2 : 1;
  uint8_t antenna : 1;
} PACK_STOP

    namespace packet {
  uint32_t ipv4(const u_char *packet, const u_char *length,
                int &start) noexcept;

  uint32_t ipv6(const u_char *packet, const u_char *length,
                int &start) noexcept;

  uint32_t arp(const u_char *packet, const u_char *length, int &start) noexcept;

  uint32_t tcp(const u_char *packet, const u_char *length, int &start) noexcept;

  uint32_t udp(const u_char *packet, const u_char *length, int &start) noexcept;
} // namespace packet