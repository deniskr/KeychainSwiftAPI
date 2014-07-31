//
//  KeychainSwiftAPITests.swift
//  KeychainSwiftAPITests
//
//  Created by Denis Krivitski on 22/7/14.
//  Copyright (c) 2014 Checkmarx. All rights reserved.
//

import UIKit
import XCTest
import KeychainSwiftAPI
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
        q.kSecAttrAccount = "Try1 account-" + rand().description
        q.kSecAttrLabel = "Try1 label"
        q.kSecReturnData = true
        q.kSecReturnAttributes = true
        q.kSecReturnRef = true
        q.kSecReturnPersistentRef = true
        
        q.kSecValueData = "Privet".dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
        
        let res1 = Keychain.secItemAdd(query: q)
        XCTAssert(res1.status == Keychain.ResultCode.errSecSuccess, "Item added sucessfully")
        
        println("Keychain secItemAdd returned: \(res1.status)")
        
        if let resUw = res1.result {
            println("\( CFGetTypeID(resUw)  )")
        } else {
            println("res is nil")
        }
        
        let q2 = Keychain.Query()
        q2.kSecAttrAccount = q.kSecAttrAccount
        q2.kSecClass = q.kSecClass
        
        let res = Keychain.secItemCopyMatching(query:q2)
        XCTAssert(res1.status == Keychain.ResultCode.errSecSuccess, "Item retrieved sucessfully")
        
        println("Status of secItemCopyMatching: \(res.status.toRaw())")
        print("Result: ")
        if let r = res.result
        {
            println("TypeID: \(CFGetTypeID(r)) Data: \(r)")
        } else {
            println("nil")
        }
        
        println(NSString(data: res.result as? NSData, encoding: NSUTF8StringEncoding))
        
        XCTAssert(res1.result != nil, "Retreived result is not nil")
        let resultDic = res1.result! as NSDictionary
        
        XCTAssert(resultDic.objectForKey("acct").isEqual(q.kSecAttrAccount!), "Account of the retrieved item matches")
        
        
        
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock() {
            // Put the code you want to measure the time of here.
        }
    }
    
}
