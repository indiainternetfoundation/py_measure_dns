/*
 * $ gcc -shared -o measuredns.so -fPIC measuredns.c 
*/

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <fcntl.h>
 #include <arpa/inet.h>
 #include <netinet/in.h>
 #include <linux/ipv6.h>
 #include <sys/time.h>
 #include <time.h>
  
 #define MAX_DNS_PACKET_SIZE 512
 #define PDM_EXTHDR_SIZE 16
  
 // DNS Flag Definitions
 #define DNS_FLAG_NO_FLAG 0x0000
 #define DNS_FLAG_PDM_METRIC 0x0001
 #define DNS_FLAG_PRE_RESOLVE4 0x0010
 #define DNS_FLAG_PRE_RESOLVE6 0x0100
  

 struct ipv6_hdr {
    uint32_t vtf;          // Version (4), Traffic Class (8), Flow Label (20)
    uint16_t payload_len;  // Payload length (excluding IPv6 header)
    uint8_t  next_header;  // Next header (IPPROTO_DSTOPTS = 60)
    uint8_t  hop_limit;    // TTL
    uint8_t  src_addr[16]; // Source IPv6 address
    uint8_t  dst_addr[16]; // Destination IPv6 address
};

 
struct dest_opt_hdr {
    uint8_t next_header;   // Next header after this extension
    uint8_t hdr_ext_len;   // Header extension length (in 8-octet units)
    uint8_t options[14];   // PDM option + padding (14 bytes)
};
 
struct pdm_option {
    uint8_t  option_type;  // 0x0F (00001111)
    uint8_t  opt_len;      // 10 (length excluding type and length fields)
    uint8_t  scale_dtlr;   // Scale for Delta Time Last Received
    uint8_t  scale_dtls;   // Scale for Delta Time Last Sent
    uint16_t psntp;        // Packet Sequence Number This Packet
    uint16_t psnlr;        // Packet Sequence Number Last Received
    uint16_t deltatlr;     // Delta Time Last Received
    uint16_t deltatls;     // Delta Time Last Sent
} __attribute__((aligned(4)));
 
 struct udp_hdr {
     uint16_t src_port;     // Source port
     uint16_t dst_port;     // Destination port (DNS = 53)
     uint16_t len;          // UDP header + payload length
     uint16_t checksum;     // Checksum (RFC 2460 pseudo-header)
 };
 
 struct dns_hdr {
     uint16_t trans_id;     // Transaction ID
     uint16_t flags;        // Flags (0x0100 for standard query)
     uint16_t questions;    // Number of questions (1)
     uint16_t answer_rrs;   // Answer RRs (0)
     uint16_t authority_rrs;// Authority RRs (0)
     uint16_t additional_rrs;// Additional RRs (0)
 };
 
 void dump_struct_bytes(const void* struct_ptr, size_t size) {
    const uint8_t* bytes = (const uint8_t*)struct_ptr;
    for (size_t i = 0; i < size; ++i) {
        printf("%02X ", bytes[i]);
    }
    printf("\n");
}

 // Structure to hold query response details
 typedef struct {
     int response_size;
     double latency_ms;
     unsigned char response[MAX_DNS_PACKET_SIZE];
 } DNSResponse;
  
 uint16_t get_random_psn() {
     uint16_t psn;
     int fd = open("/dev/urandom", O_RDONLY);
     if (fd < 0 || read(fd, &psn, sizeof(psn)) != sizeof(psn)) {
         perror("Failed to generate PSN");
         exit(EXIT_FAILURE);
     }
     close(fd);
     return psn;
 }
 
 uint16_t compute_udp_checksum(
         const struct ipv6_hdr *ip6,
         const struct udp_hdr *udp,
         const uint8_t *payload,
         size_t payload_len
     ) {
     uint32_t sum = 0;
     uint16_t word;
 
     for (int i = 0; i < 16; i += 2) {
         word = (ip6->src_addr[i] << 8) | ip6->src_addr[i+1];
         sum += word;
     }
 
     for (int i = 0; i < 16; i += 2) {
         word = (ip6->dst_addr[i] << 8) | ip6->dst_addr[i+1];
         sum += word;
     }
 
     sum += 0;
     const uint8_t *len_ptr = (const uint8_t*)&udp->len;
     sum += (len_ptr[0] << 8) | len_ptr[1];
 
     sum += IPPROTO_UDP;
 
     const uint8_t *udp_hdr = (const uint8_t*)udp;
     for (int i = 0; i < 8; i += 2) {
         word = (udp_hdr[i] << 8) | udp_hdr[i+1];
         sum += word;
     }
 
     for (size_t i = 0; i < payload_len; i++) {
         if (i % 2 == 0) {
             word = payload[i] << 8;
             if (i+1 < payload_len) word |= payload[i+1];
             sum += word;
         }
     }
 
     while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
     uint16_t checksum = ~sum;
 
     return checksum == 0 ? 0xFFFF : checksum;
 }
 
 
static inline void time_get_real_ns(struct timespec *ts) {
    clock_gettime(CLOCK_MONOTONIC_RAW, ts);
}

// Function to send a raw DNS request and receive a response
int dns_query(const char* dns_server, unsigned char* request, int req_size, DNSResponse* result, int use_ipv6, int flags) {
    int sockfd;
    struct sockaddr_storage dest, src;
    struct timespec start, end;
    socklen_t dest_len;
    int optval = 1;
 
    if (use_ipv6) {
        struct sockaddr_in6* dest6 = (struct sockaddr_in6*)&dest;
        struct sockaddr_in6* src6 = (struct sockaddr_in6*)&src;

        sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

        // Set the SO_REUSEADDR option
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
            perror("Setting SO_REUSEADDR failed");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        if (flags & DNS_FLAG_PDM_METRIC) {

            // Create and populate the PDM option
            struct pdm_option pdm;
            pdm.option_type = 0x0F;   // PDM Option Type
            pdm.opt_len = 10;         // Length (excluding type and len fields)
            pdm.scale_dtlr = 0;       // Example scale for Delta Time Last Received
            pdm.scale_dtls = 0;       // Example scale for Delta Time Last Sent
            pdm.psntp = htons(13);  // Example Packet Sequence Number This Packet
            pdm.psnlr = htons(0);     // Example Packet Sequence Number Last Received
            pdm.deltatlr = htons(0);  // Example Delta Time Last Received
            pdm.deltatls = htons(0);  // Example Delta Time Last Sent

            // Create the Destination Options Header and embed PDM
            struct dest_opt_hdr dstopt;
            memset(&dstopt, 0, sizeof(dstopt));

            dstopt.next_header = 17; // IPPROTO_UDP (Next header is UDP)
            dstopt.hdr_ext_len = 1;  // Length in 8-octet units, excluding first 8 octets

            // Copy the PDM option into the options field
            memcpy(dstopt.options, &pdm, sizeof(pdm));

            // Padding to make the total length 14 bytes (as required)
            memset(dstopt.options + sizeof(pdm), 0x00, 14 - sizeof(pdm)); // This defines padding
            memset(dstopt.options + sizeof(pdm), 0x01, 1); // This defines padding type

            int status = setsockopt(sockfd, IPPROTO_IPV6, IPV6_DSTOPTS, &dstopt, sizeof(dstopt));
            if (status < 0) {
                perror("setsockopt DSTOPT");
            }
        }

        if (sockfd < 0) {
            perror("Socket creation failed (IPv6)");
            return -1;
        }
        src6->sin6_family = AF_INET6;
        src6->sin6_port = htons(53);
        src6->sin6_addr = in6addr_any;
        if (bind(sockfd, (struct sockaddr*)src6, sizeof(*src6)) < 0) {
            perror("Binding socket to source port failed (IPv6)");
            close(sockfd);
            return -1;
        }
        dest6->sin6_family = AF_INET6;
        dest6->sin6_port = htons(53);
        if (inet_pton(AF_INET6, dns_server, &dest6->sin6_addr) <= 0) {
            perror("Invalid IPv6 address");
            close(sockfd);
            return -1;
        }
        dest_len = sizeof(struct sockaddr_in6);

  
        // Set socket options if needed
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_TCLASS, &flags, sizeof(flags)) < 0) {
            perror("Failed to set IPv6 traffic class");
        }
  
        // Example: Modify the packet to include a Destination Option (Placeholder)
        // Actual implementation will depend on specific requirements
        // Modify request buffer here if needed
    } else {
        struct sockaddr_in* dest4 = (struct sockaddr_in*)&dest;
        sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sockfd < 0) {
            perror("Socket creation failed (IPv4)");
            return -1;
        }
        dest4->sin_family = AF_INET;
        dest4->sin_port = htons(53);
        dest4->sin_addr.s_addr = inet_addr(dns_server);
        dest_len = sizeof(struct sockaddr_in);
    }
  
    time_get_real_ns(&start);
  
    if (sendto(sockfd, request, req_size, 0, (struct sockaddr*)&dest, dest_len) < 0) {
        perror("Query sending failed");
        close(sockfd);
        return -1;
    }
  
    int resp_size = recvfrom(sockfd, result->response, MAX_DNS_PACKET_SIZE, 0, (struct sockaddr*)&dest, &dest_len);
    time_get_real_ns(&end);
  
    if (resp_size < 0) {
        perror("Response receiving failed");
        close(sockfd);
        return -1;
    }
  
 
    result->latency_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_nsec - start.tv_nsec) / 1000000.0;
    result->response_size = resp_size;
  
    close(sockfd);
    return resp_size;
}
  
int query_dns(const char* dns_server, unsigned char* request, int req_size, DNSResponse* result, int use_ipv6, int flags) {
     return dns_query(dns_server, request, req_size, result, use_ipv6, flags);
}
  