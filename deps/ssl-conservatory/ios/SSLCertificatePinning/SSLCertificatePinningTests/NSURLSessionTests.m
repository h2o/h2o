//
//  NSURLSessionTests.m
//  SSLCertificatePinning
//
//  Created by Alban Diquet on 1/14/14.
//  Copyright (c) 2014 iSEC Partners. All rights reserved.
//

#import <XCTest/XCTest.h>

#import "ISPPinnedNSURLSessionDelegate.h"
#import "ISPCertificatePinning.h"
#import "SSLPinsTestUtility.h"


// Delegate we'll use for our tests
@interface NSURLSessionTaskDelegateTest : ISPPinnedNSURLSessionDelegate <NSURLSessionTaskDelegate, NSURLSessionDataDelegate>
@property BOOL connectionFinished;
@property BOOL connectionSucceeded;
@end


@interface NSURLSessionTests : XCTestCase

@end

@implementation NSURLSessionTests

- (void)setUp
{
    [super setUp];
}

- (void)tearDown
{
    [super tearDown];
}


#pragma mark SSL pinning test
- (void)testNSURLSessionSSLPinning
{
    
    // Create our SSL pins dictionnary for Twitter, iSEC and NCC
    NSDictionary *domainsToPin = [SSLPinsTestUtility setupTestSSLPinsDictionnary];
    if (domainsToPin == nil) {
        NSLog(@"Failed to pin a certificate");
    }
    
    // Save the SSL pins so that our session delegates automatically use them
    if ([ISPCertificatePinning setupSSLPinsUsingDictionnary:domainsToPin] != YES) {
        NSLog(@"Failed to pin the certificates");
    }
    
    
    // Connect to Twitter
    NSURLSessionTaskDelegateTest *sessionDelegate1 = [[NSURLSessionTaskDelegateTest alloc] init];
    NSURLSession *session1 = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration] delegate:sessionDelegate1 delegateQueue:nil];

    NSURLSessionDataTask *dataTask1 = [session1 dataTaskWithURL:[NSURL URLWithString:@"https://twitter.com/"] completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        
        sessionDelegate1.connectionFinished = YES;
        if (!error) {
            sessionDelegate1.connectionSucceeded = YES;
        }
    }];
    [dataTask1 resume];
    
    
    // Connect to iSEC
    NSURLSessionTaskDelegateTest *sessionDelegate2 = [[NSURLSessionTaskDelegateTest alloc] init];
    NSURLSession *session2 = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration] delegate:sessionDelegate2 delegateQueue:nil];
    
    NSURLSessionDataTask *dataTask2 = [session2 dataTaskWithURL:[NSURL URLWithString:@"https://www.isecpartners.com/"] completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {

        sessionDelegate2.connectionFinished = YES;
        if (!error) {
            sessionDelegate2.connectionSucceeded = YES;
        }
    }];
    [dataTask2 resume];
    
    
    // Connect to NCC Group => will fail because we pinned a wrong certificate
    NSURLSessionTaskDelegateTest *sessionDelegate3 = [[NSURLSessionTaskDelegateTest alloc] init];
    NSURLSession *session3 = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration] delegate:sessionDelegate3 delegateQueue:nil];
    
    NSURLSessionDataTask *dataTask3 = [session3 dataTaskWithURL:[NSURL URLWithString:@"https://www.nccgroup.com/"] completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {

        sessionDelegate3.connectionFinished = YES;
        if (!error) {
            sessionDelegate3.connectionSucceeded = YES;
        }
    }];
    [dataTask3 resume];

    
    // Do some polling to wait for the connections to complete
#define POLL_INTERVAL 0.2 // 200ms
#define N_SEC_TO_POLL 3.0 // poll for 3s
#define MAX_POLL_COUNT N_SEC_TO_POLL / POLL_INTERVAL
    
    NSUInteger pollCount = 0;
    while (!(sessionDelegate1.connectionFinished && sessionDelegate2.connectionFinished && sessionDelegate3.connectionFinished) && (pollCount < MAX_POLL_COUNT)) {
        NSDate* untilDate = [NSDate dateWithTimeIntervalSinceNow:POLL_INTERVAL];
        [[NSRunLoop currentRunLoop] runUntilDate:untilDate];
        pollCount++;
    }
    
    if (pollCount == MAX_POLL_COUNT) {
        XCTFail(@"Could not connect in time");
    }
    
    
    // The first two connections should succeed
    XCTAssertTrue(sessionDelegate1.connectionSucceeded, @"Connection to Twitter failed");
    XCTAssertTrue(sessionDelegate2.connectionSucceeded, @"Connection to iSEC Partners failed");
    
    // The last connection should fail
    XCTAssertFalse(sessionDelegate3.connectionSucceeded, @"Connection to NCC succeeded");
}


@end
    
    
    
    
#pragma mark Delegate class
    
@implementation NSURLSessionTaskDelegateTest
    
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

@end
