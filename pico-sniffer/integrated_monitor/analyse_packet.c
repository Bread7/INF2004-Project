/*
By @Ninjarku and @Ik0nw
Any issues found with this code can be fixed eventually :)
*/
#include <stdio.h>
#include <stdlib.h>
#include "pico/stdlib.h"
#include "pico/bootrom.h"
#include <string.h>
#include <time.h>


// packet Indexing values
#define DST_MAC 0
#define SRC_MAC 6
#define SRC_IP 26
#define DST_IP 30
#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4

#define DNS_PORT 53

#define MAX_STRING_LENGTH 500

// Get the MAC address from the packet startBufferAddr
char *getMacAddr(const unsigned char packet[74], int startBufferAddr, int addr_length)
{
    int len = addr_length - 1;
    char *addr = (char *)malloc(18); // Allocate memory for the address (17 digits + 1 for null terminator)

    // Check for memory allocation
    if (addr == NULL)
    {
        perror("Memory allocation failed");
        exit(1);
    }
    char *addr_start = addr;

    // Loop through to form MAC string array
    for (int i = 0; i < addr_length; i++)
    {
        int num_chars = snprintf(addr, 32, "%hhx", packet[startBufferAddr]);
        addr += num_chars;
        if (i < len)
        {
            // For MAC seperation
            *addr = ':';
            addr++;
        }

        startBufferAddr++;
    }

    addr = addr_start; // Reset the pointer to the start of the allocated memory
    return addr;
}

// Get the IP address from the packet startBufferAddr
char *getIpAddr(const unsigned char packet[74], int startBufferAddr, int addr_length)
{
    // Get the ip address from the packet startBufferAddr

    int len = addr_length - 1;
    char *addr = (char *)malloc(16); // Allocate memory for the address (15 digits + 1 for null terminator)

    // Check for memory allocation
    if (addr == NULL)
    {
        printf("outofmem\n");
        perror("Memory allocation failed");
        exit(1);
    }

    char *addr_start = addr;
    // Loop through to form IP string array
    for (int i = 0; i < addr_length; i++)
    {
        int num_chars = snprintf(addr, 16, "%d", packet[startBufferAddr]);
        addr += num_chars;
        if (i < len)
        {
            // For IP seperation
            *addr = '.';
            addr++;
        }
        // Increment to next part of buffer
        startBufferAddr++;
    }

    addr = addr_start; // Reset the pointer to the start of the allocated memory
    return addr;
}

// Sample check pattern for ping signature
unsigned char pingPattern[32] = {0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69};

// Check index 12 and 13 of packets
unsigned char ipv6[2] = {0x86, 0xdd};
unsigned char ipv4[2] = {0x08, 0x00};

unsigned char icmp_protocol_code[1] = {0x01};  // in index 23
unsigned char icmp_ping_req[2] = {0x08, 0x00}; // in index 34
unsigned char icmp_ping_rep[2] = {0x00, 0x00};
unsigned char arp_req_rep[2] = {0x08, 0x06};

// Match for packet pattern with the packet (unused at the moment)
int match(unsigned char *packet, unsigned char *pattern, int packetLength, int patternLength)
{
    int bufferPointer = 0;
    int patternPointer = 0;

    // Loop according to size of packet
    for (int i = 0; i < sizeof(packet); i++)
    {
        // Check button trigger
        if (packet[bufferPointer] == pattern[patternPointer])
        {
            // uart_putc(UART_ID, packet[bufferPointer]);
            // If patternPointer is fully read
            if (patternPointer == sizeof(pattern))
            {
                // Reached the end of pattern, its a full match
                patternPointer = 0;
                return 1;
            }

            // Increment patternPointer
            patternPointer++;

            // If the Packet is fully read, break the loop
            if (bufferPointer > sizeof(packet))
                break; // break out of while loop
        }
        else
        {
            // Reset the patternPointer if there is mismatch
            if (patternPointer != 0)
            {
                patternPointer = 0;
            }
        }

        // Increment the buffer
        bufferPointer++;
    }
    return 0;
}

#define MAX_DESTINATIONS 30
#define MAX_IP_STORED 10
#define THRESHOLD_COUNT 30 // Change this threshold count as needed
#define TIME_WINDOW 15    // Time window in seconds

struct Record {
    char ip[16]; // Assuming IPv4 addresses
    int count;
    int last_seen;
};

struct Destination {
    char protocol[20];
    char destination[50];
    struct Record records[MAX_IP_STORED];
    int count;
};

struct Destination trackedDestinations[MAX_DESTINATIONS];

void updateProtocolDestinationRecord(const char *protocol, const char *destination, const char *ip, int packetTime) {
    int i, j;
    int now = packetTime; // now variable holds the time of the packet
    
    for (i = 0; i < MAX_DESTINATIONS; ++i) {
        if (strcmp(trackedDestinations[i].protocol, protocol) == 0 &&
            strcmp(trackedDestinations[i].destination, destination) == 0) {
            
            // Matching protocol and destination found
            for (j = 0; j < MAX_IP_STORED; ++j) {
                if (strcmp(trackedDestinations[i].records[j].ip, ip) == 0) {
                    trackedDestinations[i].records[j].count++;
                    trackedDestinations[i].records[j].last_seen = now;
                    trackedDestinations[i].count++;
                    return;
                }
            }

            // If IP not found, add a new record or replace the oldest record
            int oldestIndex = 0;
            int oldestTime = trackedDestinations[i].records[0].last_seen;

            for (j = 1; j < MAX_IP_STORED; ++j) {
                if (trackedDestinations[i].records[j].count == 0) {
                    // Add new record
                    strcpy(trackedDestinations[i].records[j].ip, ip);
                    trackedDestinations[i].records[j].count++;
                    trackedDestinations[i].records[j].last_seen = now;
                    trackedDestinations[i].count++;
                    return;
                } else if (trackedDestinations[i].records[j].last_seen < oldestTime) {
                    oldestTime = trackedDestinations[i].records[j].last_seen;
                    oldestIndex = j;
                }
            }

            // Replace the oldest record
            strcpy(trackedDestinations[i].records[oldestIndex].ip, ip);
            trackedDestinations[i].records[oldestIndex].count = 1;
            trackedDestinations[i].records[oldestIndex].last_seen = now;
            trackedDestinations[i].count++;
            return;
        }
    }

    // If destination not found, add a new entry
    for (i = 0; i < MAX_DESTINATIONS; ++i) {
        if (strlen(trackedDestinations[i].protocol) == 0) {
            strcpy(trackedDestinations[i].protocol, protocol);
            strcpy(trackedDestinations[i].destination, destination);
            strcpy(trackedDestinations[i].records[0].ip, ip);
            trackedDestinations[i].records[0].count = 1;
            trackedDestinations[i].records[0].last_seen = now;
            trackedDestinations[i].count = 1;
            return;
        }
    }
}

bool checkThresholdAndAlert(const char *protocol, const char *destination, int currentTime) {
    int i, j;
    // char result[100];
    bool burstFlag = false;
    for (i = 0; i < MAX_DESTINATIONS; ++i) {
        if (strcmp(trackedDestinations[i].protocol, protocol) == 0 &&
            strcmp(trackedDestinations[i].destination, destination) == 0 &&
            trackedDestinations[i].count >= THRESHOLD_COUNT) {
            
            for (j = 0; j < MAX_IP_STORED; ++j) {
                if (trackedDestinations[i].records[j].count > 0) {
                    int occurrencesWithinTimeWindow = 0;
                    for (int k = 0; k < trackedDestinations[i].records[j].count; ++k) {
                        if ((currentTime - trackedDestinations[i].records[j].last_seen) <= TIME_WINDOW) {
                            occurrencesWithinTimeWindow++;
                        }
                    }
                    
                    if (occurrencesWithinTimeWindow >= THRESHOLD_COUNT) {
                        printf("ALERT: Threshold reached for protocol %s to destination %s\n", protocol, destination);
                        burstFlag = true;
                        printf("IP: %s\n", trackedDestinations[i].records[j].ip);
                    }
                }
            }
        }
    }
    if (burstFlag) {
        return true;
    }
    return false;
    // return result;
}

// Get the Packet values from packet
char *packetCheck(unsigned char *packet, int time)
{
    // initialise variables
    int pointer;
    char buffer[500];
    char protocol[5];
    char *output = (char *)calloc(MAX_STRING_LENGTH, sizeof(char)); // Allocate memory for the output
    if (output == NULL)
    {
        return NULL; // Handle allocation failure
    }

    // Print packet (57 to include time)
    for (int i = 0; i < 57; i++)
    {
        printf("%hhx ", packet[i]);
    }

    // Get MAC Addresses
    char *dst_mac = getMacAddr(packet, 0, MAC_ADDR_LEN);
    char *src_mac = getMacAddr(packet, 6, MAC_ADDR_LEN);
    // Extract IP type
    if (packet[12] == ipv4[0] && packet[13] == ipv4[1])
    {
        strncat(output, "IPv4\n", MAX_STRING_LENGTH - strlen(output));
    }
    else if (packet[12] == ipv6[0] && packet[13] == ipv6[1])
    {
        strncat(output, "IPv6\n", MAX_STRING_LENGTH - strlen(output));
    }

    // Extract Src and Dst Port
    int src_port = packet[34] + packet[35];
    // Can get connection type by checking destination port
    int dst_port = packet[36] + packet[37];

    // Extract packet type
    if (packet[34] == icmp_ping_req[0] && packet[34] == icmp_ping_req[1] && packet[23] == icmp_protocol_code[0])
    {
        strcpy(protocol, "ICMP");
        strncat(output, "Its ICMP ping request\n", MAX_STRING_LENGTH - strlen(output));
    }
    else if (packet[34] + packet[35] == icmp_ping_rep[0] + icmp_ping_rep[1] && packet[23] == icmp_protocol_code[0])
    {
        strcpy(protocol, "ICMP");
        strncat(output, "Its ICMP ping reply\n", MAX_STRING_LENGTH - strlen(output));
    }
    else if (dst_port == DNS_PORT)
    {
        strcpy(protocol, "DNS");
        strncat(output, "DNS\n", MAX_STRING_LENGTH - strlen(output));
        pointer = snprintf(buffer, MAX_STRING_LENGTH - strlen(output), "Source port: %d\n", src_port);
        strncat(output, buffer, pointer);
        pointer = snprintf(buffer, MAX_STRING_LENGTH - strlen(output), "Destination port: %d\n", dst_port);
        strncat(output, buffer, pointer);
    } 
    else if (packet[34] + packet[35] == arp_req_rep[0] + arp_req_rep[1]){
        strcpy(protocol, "ARP");
        strncat(output, "ARP\n", MAX_STRING_LENGTH - strlen(output));
    }
    else
    {
        // it is a source and destination port
        pointer = snprintf(buffer, MAX_STRING_LENGTH - strlen(output), "Source port: %d\n", src_port);
        strncat(output, buffer, pointer);
        pointer = snprintf(buffer, MAX_STRING_LENGTH - strlen(output), "Destination port: %d\n", dst_port);
        strncat(output, buffer, pointer);
    }

    // Get IPv4 Addresses
    char *src_ip = getIpAddr(packet, SRC_IP, IP_ADDR_LEN);
    char *dst_ip = getIpAddr(packet, DST_IP, IP_ADDR_LEN);

    // append comments for testing:
    pointer = snprintf(buffer, MAX_STRING_LENGTH - strlen(output), "Source IP: %s\n", src_ip);
    strncat(output, buffer, pointer);
    pointer = snprintf(buffer, MAX_STRING_LENGTH - strlen(output), "Destination IP: %s\n", dst_ip);
    strncat(output, buffer, pointer);
    pointer = snprintf(buffer, MAX_STRING_LENGTH - strlen(output), "Source Mac: %s\n", src_mac);
    strncat(output, buffer, pointer);
    pointer = snprintf(buffer, MAX_STRING_LENGTH - strlen(output), "Destination Mac: %s\n", dst_mac);
    strncat(output, buffer, pointer);

    updateProtocolDestinationRecord(protocol, dst_ip, src_ip, time); // Add the packet into the threshold
    
    // If burst threshold, append additional information into the packet
    bool burstFlag = false;
    burstFlag = checkThresholdAndAlert(protocol, dst_ip, time); // Check if it hits the threshold limit within the timeframe
    if (burstFlag) {
        pointer = snprintf(buffer, MAX_STRING_LENGTH - strlen(output), "ALERT: Threshold reached for protocol %s to destination IP: %s\n", protocol, dst_ip);
        strncat(output, buffer, pointer);
        printf("output = %s\n", output);
    }
    // Clean up allocated memory
    free(src_ip);
    free(dst_ip);
    free(src_mac);
    free(dst_mac);

    return output;
}
