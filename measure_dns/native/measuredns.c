/*
 * Compile with MinGW:
 * $ gcc -shared -o measuredns.dll -Wall measuredns_windows.c -lws2_32
 *
 * This code sends a DNS query and processes the response.
 * It supports both IPv4 and IPv6.
 * Windows-compatible version.
 */

/* Include required headers */
#include <stdint.h>     /* For uint8_t, uint16_t, etc. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ws2tcpip.h>
/* Windows socket headers must be included in this order */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <time.h>

#define MAX_DNS_PACKET_SIZE 512  // Max size of a DNS packet

// DNS Flag Definitions
#define DNS_FLAG_NO_FLAG       0x0000  // No special flag
#define DNS_FLAG_PDM_METRIC    0x0001  // Enable PDM metric extension (not fully supported on Windows)
#define DNS_FLAG_PRE_RESOLVE4  0x0010  // Pre-resolve IPv4 address
#define DNS_FLAG_PRE_RESOLVE6  0x0100  // Pre-resolve IPv6 address

// Maximum additional parameters for DNS response
#define MAX_ADDITIONAL_PARAMS 5
#define MAX_PARAM_SIZE 32  // Size of additional parameter buffer

// Structure for additional parameters
typedef struct {
    int type;  // Parameter type identifier
    unsigned char data[MAX_PARAM_SIZE]; // Parameter data buffer
} AdditionalParam;

// Structure to hold DNS response details
typedef struct {
    int response_size;  // Response size in bytes
    double latency_ms;  // Query latency in milliseconds
    unsigned char response[MAX_DNS_PACKET_SIZE];  // Buffer for DNS response

    int num_additional_params;  // Number of additional parameters
    AdditionalParam *additional_params;  // Pointer to additional parameters array
} DNSResponse;

// Generate a random Packet Sequence Number using a simpler method for MinGW
static uint16_t get_random_psn() {
    // Use time-based seed
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }
    
    return (uint16_t)(rand() & 0xFFFF);
}

/*
 * Initialize Winsock
 */
static int init_winsock() {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", result);
        return 0;
    }
    return 1;
}

/*
 * Sends a raw DNS query and receives the response.
 * Supports both IPv4 and IPv6.
 */
static int dns_query(const char* dns_server, unsigned char* request, int req_size, 
                    DNSResponse* result, int use_ipv6, int flags) {
    SOCKET sockfd;
    struct sockaddr_storage dest;
    DWORD start_time, end_time;
    int dest_len;
    int status;

    // Initialize result structure
    result->num_additional_params = 0;
    result->additional_params = (AdditionalParam *)malloc(MAX_ADDITIONAL_PARAMS * sizeof(AdditionalParam));
    if (!result->additional_params) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
 
    if (use_ipv6) {
        struct sockaddr_in6* dest6 = (struct sockaddr_in6*)&dest;

        sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (sockfd == INVALID_SOCKET) {
            fprintf(stderr, "Socket creation failed (IPv6): %d\n", WSAGetLastError());
            free(result->additional_params);
            result->additional_params = NULL;
            return -1;
        }

        // Note: PDM metrics not fully supported on Windows
        if (flags & DNS_FLAG_PDM_METRIC) {
            // Just add a dummy parameter to indicate PDM was requested
            if (result->num_additional_params < MAX_ADDITIONAL_PARAMS) {
                result->additional_params[result->num_additional_params].type = 0x0F; // PDM type
                result->additional_params[result->num_additional_params].data[0] = get_random_psn() & 0xFF;
                result->additional_params[result->num_additional_params].data[1] = (get_random_psn() >> 8) & 0xFF;
                result->num_additional_params++;
            }
        }

        memset(dest6, 0, sizeof(struct sockaddr_in6));
        dest6->sin6_family = AF_INET6;
        dest6->sin6_port = htons(53);
        
        // Use inet_pton if available, otherwise fallback
        if (inet_pton != NULL) {
            if (inet_pton(AF_INET6, dns_server, &dest6->sin6_addr) <= 0) {
                fprintf(stderr, "Invalid IPv6 address\n");
                closesocket(sockfd);
                free(result->additional_params);
                result->additional_params = NULL;
                return -1;
            }
        } else {
            // Fallback method if inet_pton isn't available in older MinGW
            fprintf(stderr, "IPv6 address conversion not supported in this MinGW version\n");
            closesocket(sockfd);
            free(result->additional_params);
            result->additional_params = NULL;
            return -1;
        }
        
        dest_len = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in* dest4 = (struct sockaddr_in*)&dest;
        sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        if (sockfd == INVALID_SOCKET) {
            fprintf(stderr, "Socket creation failed (IPv4): %d\n", WSAGetLastError());
            free(result->additional_params);
            result->additional_params = NULL;
            return -1;
        }

        memset(dest4, 0, sizeof(struct sockaddr_in));
        dest4->sin_family = AF_INET;
        dest4->sin_port = htons(53);
        dest4->sin_addr.s_addr = inet_addr(dns_server);
        dest_len = sizeof(struct sockaddr_in);
    }

    // Measure start time (in milliseconds)
    start_time = GetTickCount();

    // Send the DNS query
    status = sendto(sockfd, (const char*)request, req_size, 0, (struct sockaddr*)&dest, dest_len);
    if (status == SOCKET_ERROR) {
        fprintf(stderr, "Query sending failed: %d\n", WSAGetLastError());
        closesocket(sockfd);
        free(result->additional_params);
        result->additional_params = NULL;
        return -1;
    }

    // Prepare to receive response
    status = recvfrom(sockfd, (char*)result->response, MAX_DNS_PACKET_SIZE, 0, NULL, NULL);
    end_time = GetTickCount();

    if (status == SOCKET_ERROR) {
        fprintf(stderr, "Response receiving failed: %d\n", WSAGetLastError());
        closesocket(sockfd);
        free(result->additional_params);
        result->additional_params = NULL;
        return -1;
    }

    // Calculate latency in milliseconds
    result->latency_ms = (double)(end_time - start_time);
    result->response_size = status;

    closesocket(sockfd);
    return status;
}

// Function to clean up resources
void cleanup_dns_response(DNSResponse* result) {
    if (result && result->additional_params) {
        free(result->additional_params);
        result->additional_params = NULL;
        result->num_additional_params = 0;
    }
}

// Export symbol for DLL
__declspec(dllexport) int query_dns(
    const char* dns_server, unsigned char* request, int req_size, 
    DNSResponse* result, int use_ipv6, int flags
) {
    // Initialize Winsock (only needs to be done once)
    static int winsock_initialized = 0;
    if (!winsock_initialized) {
        if (!init_winsock()) {
            return -1;
        }
        winsock_initialized = 1;
    }
    
    return dns_query(dns_server, request, req_size, result, use_ipv6, flags);
}

// Export symbol for DLL
__declspec(dllexport) void free_dns_response(DNSResponse* result) {
    cleanup_dns_response(result);
}

// DLL entry point for Windows
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        // Initialize Winsock when DLL is loaded
        if (!init_winsock()) {
            return FALSE;
        }
        break;
    case DLL_PROCESS_DETACH:
        // Clean up Winsock when DLL is unloaded
        WSACleanup();
        break;
    }
    return TRUE;
}