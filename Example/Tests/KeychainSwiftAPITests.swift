//
//  KeychainSwiftAPITests.swift
//  KeychainSwiftAPITests
//
//  Created by Denis Krivitski on 22/7/14.
//  Copyright (c) 2014 Checkmarx. All rights reserved.
//

import UIKit
import XCTest
import Security

class KeychainSwiftAPITests: XCTestCase {
    
    var keychain : Keychain = Keychain()
    
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
        self.keychain = Keychain()
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testAdd1() {

        let q = Keychain.Query()
        q.kSecClass = Keychain.Query.KSecClassValue.kSecClassGenericPassword
        q.kSecAttrDescription = "This is a test description"
        q.kSecAttrGeneric = "Parol".dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
        q.kSecAttrAccount = "Try1 account-" + "105"
        q.kSecAttrLabel = "Try1 label"
        q.kSecReturnData = true
        q.kSecReturnAttributes = true
        q.kSecReturnRef = true
        q.kSecReturnPersistentRef = true
        
        q.kSecValueData = "Privet".dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
        
        let res1 = Keychain.secItemAdd(query: q)
        XCTAssert(res1.status == Keychain.ResultCode.errSecSuccess, "SecItemAdd returned success")
        
        println("Keychain secItemAdd returned: \(res1.status)")
        
        if let resUw = res1.result {
            println("res1 TypeID = \(CFGetTypeID(resUw)), Description = \(resUw)")
        } else {
            println("res1 is nil")
        }
        
        let q2 = Keychain.Query()
        q2.kSecAttrAccount = q.kSecAttrAccount
        q2.kSecClass = q.kSecClass
        q2.kSecReturnAttributes = true
        
        let res2 = Keychain.secItemCopyMatching(query:q2)
        XCTAssert(res2.status == Keychain.ResultCode.errSecSuccess, "SecItemCopyMatching returned success")
        
        println("Status of secItemCopyMatching: \(res2.status.toRaw())")
        if let r = res2.result
        {
            println("res2 TypeID: \(CFGetTypeID(r)) Description: \(r)")
        } else {
            println("res2 is nil")
        }
        
        
        XCTAssert(res1.result != nil, "Retreived result is not nil")
        if let r = res1.result {
            if let resultDic = r as? NSDictionary {
                XCTAssert(resultDic.objectForKey("acct")!.isEqual(q.kSecAttrAccount!), "Account of the retrieved item matches")
            }
        }
        
    }
    
    func textUseageExample()
    {
        let q = Keychain.Query()
        q.kSecClass = Keychain.Query.KSecClassValue.kSecClassGenericPassword
        q.kSecAttrDescription = "A password from my website"
        q.kSecAttrGeneric = "VerySecurePassword".dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
        q.kSecAttrAccount = "admin"
        q.kSecReturnData = true
        q.kSecReturnAttributes = true
        q.kSecReturnRef = true
        q.kSecReturnPersistentRef = true

        let r = Keychain.secItemAdd(query: q)
        if (r.status == Keychain.ResultCode.errSecSuccess) {
            println("ok")
        } else {
            println("Error saving password: \(r.status.description)")
        }

    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock() {
            // Put the code you want to measure the time of here.
        }
    }
    
}
