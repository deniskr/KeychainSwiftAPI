//
//  CXKeychainHelper.m
//  KeychainSwiftAPI
//
//  Created by Denis Krivitski on 26/11/14.
//  Copyright (c) 2014 Checkmarx. All rights reserved.
//

#import "CXKeychainHelper.h"
#import <Security/Security.h>

@implementation CXResultWithStatus
@end

@implementation CXKeychainHelper

+(CXResultWithStatus*)secItemCopyMatchingCaller:(NSDictionary*)query
{
    CXResultWithStatus* resultWithStatus = [[CXResultWithStatus alloc] init];
    CFTypeRef result = nil;
    
    resultWithStatus.status = SecItemCopyMatching((__bridge CFDictionaryRef)(query), &result);
    if (result != nil) {
        resultWithStatus.result = CFBridgingRelease(result);
    }
    
    return resultWithStatus;
}

+(CXResultWithStatus*)secItemAddCaller:(NSDictionary*)query
{
    CXResultWithStatus* resultWithStatus = [[CXResultWithStatus alloc] init];
    CFTypeRef result = nil;
    
    resultWithStatus.status = SecItemAdd((__bridge CFDictionaryRef)(query), &result);
    if (result != nil) {
        resultWithStatus.result = CFBridgingRelease(result);
    }
    
    return resultWithStatus;
}


@end
