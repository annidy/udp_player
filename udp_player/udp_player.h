//
//  udp_player.h
//  udp_player
//
//  Created by FengXing on 1/21/15.
//  Copyright (c) 2015 fengxing. All rights reserved.
//

#import <Foundation/Foundation.h>
#include "packet.h"

typedef void(^PcapPacketBlock)(const struct sniff_ip* ip, const struct sniff_udp *udp);

@interface udp_player : NSObject

@property NSString      *destIP;
@property NSUInteger    destPort;
@property (strong) PcapPacketBlock packetBlock;

- (BOOL)loadPcapFile:(NSString *) filePath;

- (BOOL)replay:(BOOL)bLoop;

- (void)stop;

@end
