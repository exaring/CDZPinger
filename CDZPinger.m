#import "CDZPinger.h"
#import "SimplePing.h"

#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_dl.h>

#define IFT_ETHER   0x6
#define RTF_LLINFO	0x400

struct rt_metrics {
	u_int32_t	rmx_locks;	/* Kernel must leave these values alone */
	u_int32_t	rmx_mtu;	/* MTU for this path */
	u_int32_t	rmx_hopcount;	/* max hops expected */
	int32_t		rmx_expire;	/* lifetime for route, e.g. redirect */
	u_int32_t	rmx_recvpipe;	/* inbound delay-bandwidth product */
	u_int32_t	rmx_sendpipe;	/* outbound delay-bandwidth product */
	u_int32_t	rmx_ssthresh;	/* outbound gateway buffer limit */
	u_int32_t	rmx_rtt;	/* estimated round trip time */
	u_int32_t	rmx_rttvar;	/* estimated rtt variance */
	u_int32_t	rmx_pksent;	/* packets sent using this route */
	u_int32_t	rmx_filler[4];	/* will be used for T/TCP later */
};

struct rt_msghdr {
	u_short	rtm_msglen;		/* to skip over non-understood messages */
	u_char	rtm_version;		/* future binary compatibility */
	u_char	rtm_type;		/* message type */
	u_short	rtm_index;		/* index for associated ifp */
	int	rtm_flags;		/* flags, incl. kern & message, e.g. DONE */
	int	rtm_addrs;		/* bitmask identifying sockaddrs in msg */
	pid_t	rtm_pid;		/* identify sender */
	int	rtm_seq;		/* for sender to identify action */
	int	rtm_errno;		/* why failed */
	int	rtm_use;		/* from rtentry */
	u_int32_t rtm_inits;		/* which metrics we are initializing */
	struct rt_metrics rtm_rmx;	/* metrics themselves */
};

#include <netinet/in.h>

struct sockaddr_inarp {
	u_char	sin_len;
	u_char	sin_family;
	u_short sin_port;
	struct	in_addr sin_addr;
	struct	in_addr sin_srcaddr;
	u_short	sin_tos;
	u_short	sin_other;
#define	SIN_PROXY	0x1
#define	SIN_ROUTER	0x2
};

#include <netinet/in.h>


#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>

#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

@interface CDZPinger () <SimplePingDelegate>

@property (nonatomic, strong) SimplePing *simplePing;
@property (nonatomic, copy) NSString *domainOrIp;

@property (nonatomic, assign) BOOL pingingDesired;

@property (nonatomic, strong) NSDate *pingStartTime;
@property (nonatomic, strong, readonly) NSMutableArray *lastPingTimes;

@end

@implementation CDZPinger

@synthesize lastPingTimes = _lastPingTimes;

- (id)initWithHost:(NSString *)domainOrIp
{
    self = [super init];
    if (self) {
        self.simplePing.delegate = self;
        self.domainOrIp = domainOrIp;
        self.averageNumberOfPings = 6;
        self.pingWaitTime = 1.0;
    }
    return self;
}

- (void)startPinging
{
    if (!self.pingingDesired && !self.simplePing) {
        self.pingingDesired = YES;
        self.simplePing = [SimplePing simplePingWithHostName:self.domainOrIp];
        self.simplePing.delegate = self;
        [self.simplePing start];
    }
}

- (void)stopPinging
{
    self.pingingDesired = NO;
    [self.simplePing stop];
    self.simplePing = nil;
}

- (void)receivedError:(NSError *)error {
    [self stopPinging];

    id delegate = self.delegate;
    if ([delegate respondsToSelector:@selector(pinger:didEncounterError:)]) {
        [delegate pinger:self didEncounterError:error];
    }
}

- (void)receivedPingFrom:(NSString *)sender withTime:(NSTimeInterval)time {
    if (self.pingingDesired) {
        dispatch_time_t popTime = dispatch_time(DISPATCH_TIME_NOW, (int64_t)(self.pingWaitTime * NSEC_PER_SEC));
        dispatch_after(popTime, dispatch_get_main_queue(), ^(void){
            [self sendPing];
        });
    }

    [self addPingTimeToRecord:time];
    __block NSTimeInterval totalTime = 0.0;
    __block NSUInteger timeCount = 0;
    [self.lastPingTimes enumerateObjectsUsingBlock:^(id obj, NSUInteger idx, BOOL *stop) {
        totalTime += [obj doubleValue];
        timeCount++;
    }];
    NSTimeInterval averageTime = totalTime/(double)timeCount;

    id delegate = self.delegate;
    if ([delegate respondsToSelector:@selector(pinger:didUpdate:withAverageSeconds:)]) {
        [delegate pinger:self didUpdate:sender withAverageSeconds:averageTime];
    }
}

- (void)sendPing
{
    [self.simplePing sendPingWithData:nil];
}

- (void)addPingTimeToRecord:(NSTimeInterval)time
{
    while (self.lastPingTimes.count >= self.averageNumberOfPings) {
        [self.lastPingTimes removeObjectAtIndex:0];
    }
    [self.lastPingTimes addObject:@(time)];
}

+ (const struct IPHeader *)ipInPacket:(NSData *)packet
{
    const struct IPHeader * ipPtr = nil;
    
    if ([packet length] >= (sizeof(IPHeader))) {
        ipPtr = (const IPHeader *) [packet bytes];
    }
    
    return ipPtr;
}

// http://stackoverflow.com/questions/10395041/getting-arp-table-on-iphone-ipad
+ (NSString *)ip2mac:(NSString *)ipAddress
{
    int found_entry;
    NSString *mAddr = nil;
    u_long addr = inet_addr([ipAddress cStringUsingEncoding:NSASCIIStringEncoding]);
    int mib[6];
    size_t needed;
    char *lim, *buf, *next;
    struct rt_msghdr *rtm;
    struct sockaddr_inarp *sin;
    struct sockaddr_dl *sdl;

    found_entry = 0;

    mib[0] = CTL_NET;
    mib[1] = PF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_INET;
    mib[4] = NET_RT_FLAGS;
    mib[5] = RTF_LLINFO;

    if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
        return nil;
    if ((buf = malloc(needed)) == NULL)
        return nil;
    if (sysctl(mib, 6, buf, &needed, NULL, 0) < 0)
        return nil;
    
    lim = buf + needed;

    for (next = buf; next < lim && mAddr == nil; next += rtm->rtm_msglen) {
        rtm = (struct rt_msghdr *)next;
        sin = (struct sockaddr_inarp *)(rtm + 1);
        sdl = (struct sockaddr_dl *)(sin + 1);

        if (addr) {
            if (addr != sin->sin_addr.s_addr)
                continue;
            found_entry = 1;
        }

        if (sdl->sdl_alen) {
            u_char *cp = (u_char *)LLADDR(sdl);
            mAddr = [NSString stringWithFormat:@"%x:%x:%x:%x:%x:%x", cp[0], cp[1], cp[2], cp[3], cp[4], cp[5]];
        }
        else {
            mAddr = nil;
        }
    }
    
    if (found_entry == 0) {
        return nil;
    }
    else {
        return mAddr;
    }
}

#pragma mark SimplePingDelegate methods

- (void)simplePing:(SimplePing *)pinger didStartWithAddress:(NSData *)address
{
    if (self.pingingDesired) [self sendPing];
}

- (void)simplePing:(SimplePing *)pinger didSendPacket:(NSData *)packet
{
    self.pingStartTime = [NSDate date];

    //NSLog(@"#%u sent", (unsigned int) OSSwapBigToHostInt16(((const ICMPHeader *) [packet bytes])->sequenceNumber));
}

- (void)simplePing:(SimplePing *)pinger didReceivePingResponsePacket:(NSData *)packet
{
    const struct IPHeader *ipHeader = [CDZPinger ipInPacket:packet];
    NSTimeInterval pingTime = [[NSDate date] timeIntervalSinceDate:self.pingStartTime];
    NSString *sender = nil;
    
    if (ipHeader != nil) {
        sender = [NSString stringWithFormat:@"%d.%d.%d.%d", ipHeader->sourceAddress[0],
            ipHeader->sourceAddress[1], ipHeader->sourceAddress[2], ipHeader->sourceAddress[3]];
    }

    [self receivedPingFrom:sender withTime:pingTime];

    //NSLog(@"#%u received from %@", (unsigned int) OSSwapBigToHostInt16([SimplePing icmpInPacket:packet]->sequenceNumber), sender);
}

- (void)simplePing:(SimplePing *)pinger didFailWithError:(NSError *)error
{
    [self receivedError:error];
}

- (void)simplePing:(SimplePing *)pinger didFailToSendPacket:(NSData *)packet error:(NSError *)error
{
    [self receivedError:error];
}

#pragma mark Property overrides

- (NSMutableArray *)lastPingTimes
{
    if (!_lastPingTimes) {
        _lastPingTimes = [NSMutableArray array];
    }
    return _lastPingTimes;
}

@end
