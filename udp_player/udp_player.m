//
//  udp_player.m
//  udp_player
//
//  Created by FengXing on 1/21/15.
//  Copyright (c) 2015 fengxing. All rights reserved.
//

#import "udp_player.h"
#include "pcap.h"
#import <CoreFoundation/CoreFoundation.h> 
#include <sys/socket.h> 
#include <netinet/in.h>
#include <arpa/inet.h>
#include "packet.h"


#define SIZE_UDP        8               /* length of UDP header */

static double tv_to_double(const struct timeval *tv)
{
    return (double)tv->tv_sec + (double)tv->tv_usec / 1000000.0;
}

static double get_time()
{
    struct timeval tv;
    gettimeofday(&tv,NULL);
    return tv_to_double(&tv);
}

@implementation udp_player
{
    pcap_t *_pcap_file;
    NSThread *_worker_thread;
    BOOL _playing;
    CFSocketRef _cfsocket;
}

- (instancetype)init
{
    if (self = [super init]) {

    }
    return self;
}

- (void)dealloc
{
    [self stop];
}

- (BOOL)loadPcapFile:(NSString *)filePath
{
    char errbuf[PCAP_ERRBUF_SIZE];
    // Open the capture file.
    pcap_t *pcap_file = pcap_open_offline([filePath UTF8String], errbuf);
    if (!pcap_file) {
        NSLog(@"Can't open original file %@ for reading", filePath);
        NSLog(@"Error %s", errbuf);
        return NO;
    }
    
    if (_pcap_file) pcap_close(_pcap_file);
    _pcap_file = pcap_file;
    //
    return YES;
}

- (BOOL)replay:(BOOL)bLoop
{
    
    _cfsocket = CFSocketCreate(kCFAllocatorDefault, PF_INET, SOCK_DGRAM, IPPROTO_UDP, 0, 0, NULL);
    if (!_cfsocket) {
        NSLog(@"CFSocketCreate fialed!");
        return NO;
    }
    _worker_thread = [[NSThread alloc] initWithTarget:self selector:@selector(sendRoutine:) object:@(bLoop)];
    _worker_thread.name = @"UDP-Send";
    _playing = YES;
    [_worker_thread start];
    
    return YES;
}

- (void)stop
{
    _playing = NO;
    while ([_worker_thread isExecuting]) {
        [NSThread sleepForTimeInterval:0.1];
    }
    if (_cfsocket) {
        close(CFSocketGetNative(_cfsocket));
        CFRelease(_cfsocket), _cfsocket = 0;
    }
    if (_pcap_file)
        pcap_close(_pcap_file), _pcap_file = 0;
}

- (int)sendRoutine:(id)arg
{
    if (!_pcap_file) {
        return 1;
    }
    struct pcap_pkthdr    *next_packet_header;
    const char     *next_packet_data;
    double playback_start_time;
    double capture_start_time;
    BOOL loop = (BOOL)arg;
    off_t loop_start = 0;
    if (loop) {
        loop_start = ftello(pcap_file(_pcap_file));
    }

    
    playback_start_time = capture_start_time = 0;
    next_packet_header = (struct pcap_pkthdr*) calloc(1,sizeof(struct pcap_pkthdr));
    do {
        next_packet_data = (const char*) pcap_next(_pcap_file, next_packet_header);
        if (!next_packet_data) {
            if (loop) { // 重新开始or第一次进入
                fseeko(pcap_file(_pcap_file), loop_start, SEEK_SET);
                capture_start_time = 0;
                continue;
            }
            break;
        }
        if (capture_start_time == 0) {
            capture_start_time = tv_to_double(&next_packet_header->ts);
            playback_start_time = get_time();
        }
        
        double pkt_time = tv_to_double(&next_packet_header->ts) - capture_start_time;
        double playback_time = get_time() - playback_start_time;
        if (playback_time < pkt_time) {
            [NSThread sleepForTimeInterval:pkt_time-playback_time];
        }
        [self sendPacket:next_packet_data];

    } while (_playing);
    NSLog(@"Thread exit");
    free(next_packet_header);
    return 0;
}

- (void)sendPacket:(const char *)packet
{
    /* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_udp *udp;            /* The UDP header */
    const char *payload;                    /* Packet payload */
    
    int size_ip;
    int size_payload;
    
    
    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHER);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    
    /* print source and destination IP addresses */
    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));
    
    /* determine protocol */
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            break;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
    }
    
    /*
     *  OK, this packet is UDP.
     */
    
    /* define/compute tcp header offset */
    udp = (struct sniff_udp*)(packet + SIZE_ETHER + SIZE_UDP);
    
    printf("   Src port: %d\n", ntohs(udp->uh_sport));
    printf("   Dst port: %d\n", ntohs(udp->uh_dport));
    
    /* define/compute udp payload (segment) offset */
    payload = (const char *)(packet + SIZE_ETHER + size_ip + SIZE_UDP);
    
    /* compute udp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
    if (size_payload > ntohs(udp->uh_len))
        size_payload = ntohs(udp->uh_len);
    
    /*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     */
    if (size_payload > 0) {
        printf("   Payload (%d bytes):\n", size_payload);
    }
    if (self.packetBlock) {
        self.packetBlock(ip, udp);
    }
    struct sockaddr_in destinationAddress;
    socklen_t sockaddr_destaddr_len = sizeof(destinationAddress);
    memset(&destinationAddress, 0, sockaddr_destaddr_len);
    destinationAddress.sin_len = sockaddr_destaddr_len;
    destinationAddress.sin_family = AF_INET;
    destinationAddress.sin_port = htons(self.destPort);
    destinationAddress.sin_addr.s_addr = inet_addr([self.destIP UTF8String]);
    NSData *destinationAddressData = [NSData dataWithBytes:&destinationAddress length:sizeof(destinationAddress)];
    CFSocketError socket_error;
    socket_error = CFSocketSendData(_cfsocket, (CFDataRef) destinationAddressData,
                                    (CFDataRef)[NSData dataWithBytes:payload length:size_payload],
                                    0);
    if (socket_error < 0) {
        NSLog(@"%@", [NSError errorWithDomain:@"AsyncSocketErrorDomain" code:socket_error userInfo:nil]);
    }
}
@end
