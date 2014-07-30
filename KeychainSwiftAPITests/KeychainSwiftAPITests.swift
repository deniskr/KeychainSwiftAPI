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
    
    func testExample() {
        // This is an example of a functional test case.
        // kSecAttrAuthenticationType.takeUnretainedValue() as CFTypeRef

        let q = Keychain.Query()
        q.kSecClass = Keychain.Query.KSecClassValue.kSecClassGenericPassword
        q.kSecReturnData = true
        q.kSecReturnAttributes = true
        q.kSecReturnRef = true
        q.kSecReturnPersistentRef = true
        
        q.kSecValueData = "Privet".dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
        
        let res1 = Keychain.secItemAdd(query: q)
        
        if let resUw = res1.result {
            println("\( CFGetTypeID(resUw)  )")
        } else {
            println("res is nil")
        }
        let res = Keychain.secItemCopyMatching(query:q)

        println(NSString(data: res.result as? NSData, encoding: NSUTF8StringEncoding))
        

        
        XCTAssert(res.status == Keychain.ResultCode.errSecSuccess, "Pass")
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock() {
            // Put the code you want to measure the time of here.
        }
    }
    
}
