//
//  SSLPinsTestUtility.m
//  SSLCertificatePinning
//
//  Created by Alban Diquet on 2/2/14.
//  Copyright (c) 2014 iSEC Partners. All rights reserved.
//

#import "SSLPinsTestUtility.h"
#import "ISPCertificatePinning.h"

@implementation SSLPinsTestUtility


+ (NSData*)loadCertificateFromFile:(NSString*)fileName {
    NSString *certPath =  [[NSBundle bundleForClass:[self class]] pathForResource:fileName ofType:@"der"];
    NSData *certData = [[NSData alloc] initWithContentsOfFile:certPath];
    return certData;
}


+ (NSDictionary*) setupTestSSLPinsDictionnary {
    // Build our dictionnary of domain => certificates
    NSMutableDictionary *domainsToPin = [[NSMutableDictionary alloc] init];
    
    
    // For Twitter, we pin the anchor/CA certificate
    NSData *twitterCertData = [SSLPinsTestUtility loadCertificateFromFile:@"VeriSignClass3PublicPrimaryCertificationAuthority-G5"];
    if (twitterCertData == nil) {
        NSLog(@"Failed to load a certificate");
        return nil;
    }
    NSArray *twitterTrustedCerts = [NSArray arrayWithObject:twitterCertData];
    [domainsToPin setObject:twitterTrustedCerts forKey:@"twitter.com"];
    
    
    // For iSEC, we pin the server/leaf certificate
    NSData *isecCertData = [SSLPinsTestUtility loadCertificateFromFile:@"www.isecpartners.com"];
    if (isecCertData == nil) {
        NSLog(@"Failed to load a certificate");
        return nil;
    }
    // We also pin Twitter's CA cert just to show that you can pin multiple certs to a single domain
    // This is useful when transitioning between two certificates on the server
    // The connection will be succesful if at least one of the pinned certs is found in the server's certificate trust chain
    NSArray *iSECTrustedCerts = [NSArray arrayWithObjects:isecCertData, twitterCertData, nil];
    [domainsToPin setObject:iSECTrustedCerts forKey:@"www.isecpartners.com"];
    
    
    // For NCC group, we pin an invalid certificate (Twitter's)
    NSArray *NCCTrustedCerts = [NSArray arrayWithObject:twitterCertData];
    [domainsToPin setObject:NCCTrustedCerts forKey:@"www.nccgroup.com"];
    
    return domainsToPin;
}

@end
