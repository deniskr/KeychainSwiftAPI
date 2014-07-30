//
//  Keychain.swift
//  KeychainSwiftAPI
//
//  Created by Denis Krivitski on 22/7/14.
//  Copyright (c) 2014 Checkmarx. All rights reserved.
//

import Foundation
import Security

public class Keychain
{
    
    public enum ResultCode : OSStatus {
        case errSecSuccess                  = 0        // No error.
        case errSecUnimplemented            = -4       // Function or operation not implemented.
        case errSecParam                    = -50      // One or more parameters passed to the function were not valid.
        case errSecAllocate                 = -108     // Failed to allocate memory.
        case errSecNotAvailable             = -25291   // No trust results are available.
        case errSecAuthFailed               = -25293   // Authorization/Authentication failed.
        case errSecDuplicateItem            = -25299   // The item already exists.
        case errSecItemNotFound             = -25300   // The item cannot be found.
        case errSecInteractionNotAllowed    = -25308   // Interaction with the Security Server is not allowed.
        case errSecDecode                   = -26275   // Unable to decode the provided data.
    }
    
    
    

    public class Query {
        public init(){}
        
        public var kSecClass : KSecClassValue?
        private let kSecClassKey = "class"
        
        public enum KSecClassValue : String {
            
            case kSecClassGenericPassword   = "genp"
            case kSecClassInternetPassword  = "inet"
            case kSecClassCertificate       = "cert"
            case kSecClassKey               = "keys"
            case kSecClassIdentity          = "idnt"
            
        }
        
        public var kSecReturnData : Bool = false
        private let kSecReturnDataKey = "r_Data"
        
        public var kSecReturnAttributes : Bool = false
        private let kSecReturnAttributesKey = "r_Attributes"
        
        public var kSecReturnRef : Bool = false
        private let kSecReturnRefKey = "r_Ref"
        
        public var kSecReturnPersistentRef : Bool = false
        private let kSecReturnPersistentRefKey = "r_PersistentRef"
        
        
        
        
        public var kSecValueData : NSData?
        private let kSecValueDataKey = "v_Data"
        
        public var kSecValueRef : KSecValueRefValue?
        private let kSecValueRefKey = "v_Ref"
        
        public enum KSecValueRefValue {
            case Key(SecKeyRef)
            case Certificate(SecCertificateRef)
            case Identity(SecIdentityRef)
        }
        
        
        public var kSecValuePersistentRef : NSData?
        private let kSecValuePersistentRefKey = "v_PersistentRef"
        
        
        
        public func toNSDictionary() -> NSDictionary
        {
            let dic = NSMutableDictionary()

            if let v = self.kSecClass {
                dic.setObject(v.toRaw(), forKey: kSecClassKey)
            }
            
            dic.setObject(NSNumber(bool: self.kSecReturnData), forKey: self.kSecReturnDataKey)
            dic.setObject(NSNumber(bool: self.kSecReturnAttributes), forKey: self.kSecReturnAttributesKey)
            dic.setObject(NSNumber(bool: self.kSecReturnRef), forKey: self.kSecReturnRefKey)
            dic.setObject(NSNumber(bool: self.kSecReturnPersistentRef), forKey: self.kSecReturnPersistentRefKey)
            
            
            
            if let v = self.kSecValueData {
                dic.setObject(v, forKey: self.kSecValueDataKey)
            }
            
            if let v = self.kSecValueRef {
                switch v {
                case let .Key(val):
                    dic.setObject(val, forKey: self.kSecValueRefKey)

                case let .Certificate(val):
                    dic.setObject(val, forKey: self.kSecValueRefKey)

                case let .Identity(val):
                    dic.setObject(val, forKey: self.kSecValueRefKey)

                }
            }
            
            if let v = self.kSecValuePersistentRef {
                dic.setObject(v, forKey: self.kSecValuePersistentRefKey)
            }

            return dic
        }
    }
    
    public class func secItemAdd(#query : Query) -> (status: ResultCode, result: NSObject?) {

        let dic = query.toNSDictionary()
        let result = UnsafePointer<Unmanaged<AnyObject>?>.alloc(1)
        let statusRaw = SecItemAdd(dic,result)
        let status = ResultCode.fromRaw(statusRaw)!
        
        if status == .errSecSuccess {
            let resultCasted = UnsafePointer<AnyObject?>(result)
            let resultValue = resultCasted.memory
            return (status: status, result: resultValue as? NSObject)
        } else {
            return (status: status, result: nil)
        }
        
    }
    
    
    public class func secItemCopyMatching(#query : Query) -> (status: ResultCode, result: NSObject?)
    {
        let dic = query.toNSDictionary()
        let result = UnsafePointer<Unmanaged<AnyObject>?>.alloc(1)
        let statusRaw = SecItemCopyMatching(dic, result)
        let status = ResultCode.fromRaw(statusRaw)!

        if  status == ResultCode.errSecSuccess {
            
            // This cast is done to avoid compiler crash in XCode6-beta4
            let resultCasted = UnsafePointer<AnyObject?>(result)
            let resultValue = resultCasted.memory
            
            return (status: status, result: resultValue as? NSObject)

        } else {
            return (status: status, result: nil)
        }
        
        
    }
    
    public class func test()
    {
        let q = Query()
        q.kSecClass = .kSecClassCertificate
        secItemCopyMatching(query:q)
    }

}