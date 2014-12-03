# KeychainSwiftAPI

This Keychain Swift API library is a wrapper of iOS C Keychain Framework.
It allows easily and securely storing sensitive data in secure keychain store
in Swift projects. Interfacing with the original C keychain API is combersome from
Swift, and is prone to errors which lead to security vulnerabilities. This
library is written according to the best security coding practices and guidelines.

## Usage
<code>
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
</code>

## Requirements

## Installation

KeychainSwiftAPI is available through [CocoaPods](http://cocoapods.org). To install
it, simply add the following line to your Podfile:

    pod "KeychainSwiftAPI"

## Author

Denis Krivitski, denis.krivitski@checkmarx.com


## Sponsor

[Checkmarx](http://www.checkmarx.com) LTD. Checkmarx is a provider of code analysis tools, 
static code analysis, software code analysis. We help developers make flawless applications.

## License

KeychainSwiftAPI is available under the MIT license. See the LICENSE file for more info.

