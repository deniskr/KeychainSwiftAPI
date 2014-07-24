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

class KeychainSwiftAPITests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testExample() {
        // This is an example of a functional test case.
        
        let res = secItemCopyMatching(query: ["1" as NSString : 1])
        
        XCTAssert(res.status == 0, "Pass")
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measureBlock() {
            // Put the code you want to measure the time of here.
        }
    }
    
}
