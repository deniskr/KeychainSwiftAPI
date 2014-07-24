//
//  Keychain.swift
//  KeychainSwiftAPI
//
//  Created by Denis Krivitski on 22/7/14.
//  Copyright (c) 2014 Checkmarx. All rights reserved.
//

import Foundation
import Security

public func secItemCopyMatching(#query : Dictionary<NSObject,Any>) -> (status: Int, result: CFTypeRef?)
{
    
    return (status: 0, result: nil)
}
