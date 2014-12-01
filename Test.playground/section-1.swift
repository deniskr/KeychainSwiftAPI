// Playground - noun: a place where people can play

import UIKit
import Security
import KeychainSwiftAPI



let q = Keychain.Query()
q.kSecClass = Keychain.Query.KSecClassValue.kSecClassGenericPassword
q.kSecAttrDescription = "This is a test description"
q.kSecAttrGeneric = "Parol".dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)
q.kSecAttrAccount = "Try1 account-" + "101"
q.kSecAttrLabel = "Try1 label"
q.kSecReturnData = true
q.kSecReturnAttributes = true
q.kSecReturnRef = true
q.kSecReturnPersistentRef = true

q.kSecValueData = "Privet".dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: false)

let res1 = Keychain.secItemAdd(query: q)

println("Keychain secItemAdd returned: \(res1.status)")

if let resUw = res1.result {
    println("\( CFGetTypeID(resUw)  )")
} else {
    println("res is nil")
}

let q2 = Keychain.Query()
q2.kSecAttrAccount = q.kSecAttrAccount
q2.kSecClass = q.kSecClass

//let res = Keychain.secItemCopyMatching(query:q2)

let query = q2
let dic : NSDictionary = query.toNSDictionary()
let result = UnsafeMutablePointer<Unmanaged<AnyObject>?>.alloc(1)

//@availability(iOS, introduced=2.0)
//func SecItemCopyMatching(query: CFDictionary!, result: UnsafeMutablePointer<Unmanaged<AnyObject>?>) -> OSStatus

let statusRaw : OSStatus = SecItemCopyMatching(dic, result)
let status = Keychain.ResultCode.fromRaw(statusRaw)
let resultCasted = UnsafePointer<AnyObject?>(result)
let resultValue : AnyObject? = resultCasted.memory

//let resultValue: AnyObject? = result.memory?.takeUnretainedValue()

let res = (status: status, result: resultValue as? NSObject)



println("Status of secItemCopyMatching: \(res.status.toRaw())")
print("Result: ")
if let r = res.result
{
    println("TypeID: \(CFGetTypeID(r)) Data: \(r)")
} else {
    println("nil")
}

//println(NSString(data: res.result! as NSData , encoding: NSUTF8StringEncoding))