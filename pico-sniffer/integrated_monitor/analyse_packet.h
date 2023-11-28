/*
By @Ninjarku & @Ik0nw
Any issues found with this code can be fixed eventually:)
*/
#ifndef PACKET_UTILS_H
#define PACKET_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include "pico/stdlib.h"
#include "pico/bootrom.h"
#include <string.h>

#define DST_MAC 0
#define SRC_MAC 6
#define SRC_IP 26
#define DST_IP 30
#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define DNS_PORT 53
#define MAX_STRING_LENGTH 500

char *getMacAddr(const unsigned char packet[74], int startBufferAddr, int addr_length);
char *getIpAddr(const unsigned char packet[74], int startBufferAddr, int addr_length);
int match(unsigned char *packet, unsigned char *pattern, int packetLength, int patternLength);
char *packetCheck(unsigned char *packet, int time);
bool checkThresholdAndAlert(const char *protocol, const char *destination, int currentTime);
void updateProtocolDestinationRecord(const char *protocol, const char *destination, const char *ip, int packetTime);

#endif  // PACKET_UTILS_H
