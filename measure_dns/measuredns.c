/*
 * $ gcc -shared -o measuredns.so -fPIC measuredns.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>

#define MAX_DNS_PACKET_SIZE 512

// Structure to hold query response details
typedef struct {
    int response_size;
    double latency_ms;
    unsigned char response[MAX_DNS_PACKET_SIZE];
} DNSResponse;

// Function to send a raw DNS request and receive a response
int dns_query(const char* dns_server, unsigned char* request, int req_size, DNSResponse* result) {
    int sockfd;
    struct sockaddr_in dest;
    struct timeval start, end;

    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_server);

    gettimeofday(&start, NULL); // Start RTT measurement

    // Send the DNS request
    if (sendto(sockfd, request, req_size, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
        perror("Query sending failed");
        close(sockfd);
        return -1;
    }

    // Receive the response
    socklen_t len = sizeof(dest);
    int resp_size = recvfrom(sockfd, result->response, MAX_DNS_PACKET_SIZE, 0, (struct sockaddr*)&dest, &len);
    
    gettimeofday(&end, NULL); // End RTT measurement

    if (resp_size < 0) {
        perror("Response receiving failed");
        close(sockfd);
        return -1;
    }

    // Calculate latency in milliseconds
    result->latency_ms = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;
    result->response_size = resp_size;

    close(sockfd);
    return resp_size;
}

// C function interface for Python
int query_dns(const char* dns_server, unsigned char* request, int req_size, DNSResponse* result) {
    return dns_query(dns_server, request, req_size, result);
}
