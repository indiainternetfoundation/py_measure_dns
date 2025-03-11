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

// Additional parameters storage
#define MAX_ADDITIONAL_PARAMS 5
#define MAX_PARAM_SIZE 32

typedef struct {
    int type;  // Identifier for the parameter type
    unsigned char data[MAX_PARAM_SIZE]; // Buffer to store the parameter
} AdditionalParam;

// Structure to hold query response details
typedef struct {
    int response_size;
    double latency_ns;
    unsigned char response[MAX_DNS_PACKET_SIZE];

    int num_additional_params;
    // AdditionalParam additional_params[MAX_ADDITIONAL_PARAMS];
    AdditionalParam *additional_params;
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

static inline void time_get_real_ns(struct timespec *ts) {
    clock_gettime(CLOCK_MONOTONIC_RAW, ts);
}

// Function to send a raw DNS request and receive a response
int dns_query(const char* dns_server, unsigned char* request, int req_size, DNSResponse* result, int use_ipv6, int flags) {
    int sockfd;
    struct sockaddr_storage dest;
    struct timespec start, end;
    socklen_t dest_len;
    int opt = 1;

    // Inside dns_query, after receiving the message
    result->num_additional_params = 0;
    result->additional_params = (AdditionalParam *)malloc(MAX_ADDITIONAL_PARAMS * sizeof(AdditionalParam));
 
    if (use_ipv6) {
        struct sockaddr_in6* dest6 = (struct sockaddr_in6*)&dest;

        sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

        if (flags & DNS_FLAG_PDM_METRIC) {

            // Create and populate the PDM option
            struct pdm_option pdm;
            pdm.option_type = 0x0F;   // PDM Option Type
            pdm.opt_len = 10;         // Length (excluding type and len fields)
            pdm.scale_dtlr = 0;       // Example scale for Delta Time Last Received
            pdm.scale_dtls = 0;       // Example scale for Delta Time Last Sent
            pdm.psntp = htons(get_random_psn());  // Example Packet Sequence Number This Packet
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
            // memset(dstopt.options + sizeof(pdm), 0x01, 1); // This defines padding type

            int status = setsockopt(sockfd, IPPROTO_IPV6, IPV6_DSTOPTS, &dstopt, sizeof(dstopt));
            if (status < 0) {
                perror("setsockopt DSTOPT");
            }

            // Allow the kernel to pass destination options to the application
            if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVDSTOPTS, &opt, sizeof(opt)) < 0) {
                perror("setsockopt IPV6_RECVDSTOPTS");
                close(sockfd);
                exit(EXIT_FAILURE);
            }
        }

        if (sockfd < 0) {
            perror("Socket creation failed (IPv6)");
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


    // Prepare to receive the message along with ancillary data
    char ctrl_buf[1024];
    struct iovec iov;
    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));

    iov.iov_base = result->response;
    iov.iov_len = MAX_DNS_PACKET_SIZE;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    msg.msg_control = ctrl_buf;
    msg.msg_controllen = sizeof(ctrl_buf);

    ssize_t resp_size = recvmsg(sockfd, &msg, 0);

    time_get_real_ns(&end);

    if (resp_size < 0) {
        perror("Response receiving failed");
        close(sockfd);
        return -1;
    }

    // Iterate through ancillary data to find the destination options header
    struct cmsghdr *cmsg;
    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_DSTOPTS) {
            // printf("Received IPv6 Destination Options header!\n");
            // cmsg->cmsg_data points to the received destination options header.
            // You can cast it to a structure pointer (if defined) to process it.
            // For example:
            // struct ipv6_destopt *dstopts = (struct ipv6_destopt *)CMSG_DATA(cmsg);
            if (result->num_additional_params < MAX_ADDITIONAL_PARAMS) {
                // result->additional_params[param_index].type = IPV6_DSTOPTS;
                // memcpy(result->additional_params[param_index].data, CMSG_DATA(cmsg), MAX_PARAM_SIZE);
                result->additional_params[result->num_additional_params].type = IPV6_DSTOPTS;
                memcpy(result->additional_params[result->num_additional_params].data, CMSG_DATA(cmsg), MAX_PARAM_SIZE);
                result->num_additional_params++;
            }
        }
    }

    result->latency_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);
    result->response_size = resp_size;

    close(sockfd);
    return resp_size;
}

int query_dns(
    const char* dns_server, 
    unsigned char* request, 
    int req_size, 
    DNSResponse* result, 
    int use_ipv6, 
    int flags
) {
    return dns_query(dns_server, request, req_size, result, use_ipv6, flags);
}
  