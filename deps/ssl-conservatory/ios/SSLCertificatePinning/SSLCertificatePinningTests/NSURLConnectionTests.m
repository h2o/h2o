//
//  NSURLConnectionTests.m
//  SSLCertificatePinning
//
//  Created by Alban Diquet on 1/14/14.
//  Copyright (c) 2014 iSEC Partners. All rights reserved.
//

#import <XCTest/XCTest.h>

#import "ISPPinnedNSURLConnectionDelegate.h"
#import "ISPCertificatePinning.h"
#import "SSLPinsTestUtility.h"


// Delegate we'll use for our tests
@interface NSURLConnectionDelegateTest : ISPPinnedNSURLConnectionDelegate <NSURLConnectionDelegate>
    @property BOOL connectionFinished;
    @property BOOL connectionSucceeded;
@end



@interface NSURLConnectionTests : XCTestCase

@end


@implementation NSURLConnectionTests


- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}

#pragma mark SSL pinning test


// This is sample code to demonstrate how to implement certificate pinning with NSURLConnection
- (void)testNSURLConnectionSSLPinning
{

    // Create our SSL pins dictionnary for Twitter, iSEC and NCC
    NSDictionary *domainsToPin = [SSLPinsTestUtility setupTestSSLPinsDictionnary];
    if (domainsToPin == nil) {
        NSLog(@"Failed to pin a certificate");
    }
    
    
    // Save the SSL pins so that our connection delegates automatically use them
    if ([ISPCertificatePinning setupSSLPinsUsingDictionnary:domainsToPin] != YES) {
        NSLog(@"Failed to pin the certificates");
    }
    
    // Connect to Twitter
    NSURLRequest *request = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://twitter.com/"]];
    NSURLConnectionDelegateTest *connectionDelegate = [[NSURLConnectionDelegateTest alloc] init];
    NSURLConnection *connection=[[NSURLConnection alloc] initWithRequest:request delegate:connectionDelegate];
    [connection start];
    
    // Connect to iSEC
    NSURLRequest *request2 = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.isecpartners.com/"]];
    NSURLConnectionDelegateTest *connectionDelegate2 = [[NSURLConnectionDelegateTest alloc] init];
    NSURLConnection *connection2 = [[NSURLConnection alloc] initWithRequest:request2 delegate:connectionDelegate2];
    [connection2 start];
    
    // Connect to NCC Group => will fail because we pinned a wrong certificate
    NSURLRequest *request3 = [NSURLRequest requestWithURL:[NSURL URLWithString:@"https://www.nccgroup.com/"]];
    NSURLConnectionDelegateTest *connectionDelegate3 = [[NSURLConnectionDelegateTest alloc] init];
    NSURLConnection *connection3 = [[NSURLConnection alloc] initWithRequest:request3 delegate:connectionDelegate3];
    [connection3 start];
    
    
    // Do some polling to wait for the connections to complete
#define POLL_INTERVAL 0.2 // 200ms
#define N_SEC_TO_POLL 3.0 // poll for 3s
#define MAX_POLL_COUNT N_SEC_TO_POLL / POLL_INTERVAL
    
    NSUInteger pollCount = 0;
    while (!(connectionDelegate.connectionFinished && connectionDelegate2.connectionFinished && connectionDelegate3.connectionFinished) && (pollCount < MAX_POLL_COUNT)) {
        NSDate* untilDate = [NSDate dateWithTimeIntervalSinceNow:POLL_INTERVAL];
        [[NSRunLoop currentRunLoop] runUntilDate:untilDate];
        pollCount++;
    }
    
    if (pollCount == MAX_POLL_COUNT) {
        XCTFail(@"Could not connect in time");
    }
    
    
    // The first two connections should succeed
    XCTAssertTrue(connectionDelegate.connectionSucceeded, @"Connection to Twitter failed");
    XCTAssertTrue(connectionDelegate2.connectionSucceeded, @"Connection to iSEC Partners failed");
    
    // The last connection should fail
    XCTAssertFalse(connectionDelegate3.connectionSucceeded, @"Connection to NCC succeeded");
}


@end


#pragma mark Delegate class

@implementation NSURLConnectionDelegateTest

@synthesize connectionSucceeded;
@synthesize connectionFinished;

-(instancetype) init {
    if (self = [super init])
    {
        self.connectionSucceeded = NO;
        self.connectionFinished = NO;
    }
    return self;
}


- (void)connectionDidFinishLoading:(NSURLConnection *)connection {
    self.connectionSucceeded = YES;
    self.connectionFinished = YES;
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error {
    self.connectionSucceeded = NO;
    self.connectionFinished = YES;
}

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data {
    self.connectionSucceeded = YES;
    self.connectionFinished = YES;
}

- (NSCachedURLResponse *)connection:(NSURLConnection *)connection willCacheResponse:(NSCachedURLResponse *)cachedResponse {
    return cachedResponse;
}

- (void)connection:(NSURLConnection *)connection didReceiveResponse:(NSURLResponse *)response {
    self.connectionSucceeded = YES;
    self.connectionFinished = YES;
}

- (NSURLRequest *)connection:(NSURLConnection *)connection willSendRequest:(NSURLRequest *)request redirectResponse:(NSURLResponse *)redirectResponse {
    return request;
}

@end