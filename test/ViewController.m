//
//  ViewController.m
//  test
//
//  Created by FengXing on 1/21/15.
//  Copyright (c) 2015 fengxing. All rights reserved.
//

#import "ViewController.h"
#import "udp_player.h"

@interface ViewController ()

@property udp_player *player;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    self.player = [[udp_player alloc] init];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)start:(id)sender
{
    self.player.destIP = @"127.0.0.1";
    self.player.destPort = 3000;
    [self.player loadPcapFile:[[NSBundle mainBundle] pathForResource:@"dump" ofType:@"cap"]];
    [self.player replay:NO];
}

- (IBAction)stop:(id)sender
{
    [self.player stop];
}

@end
