// Playground - noun: a place where people can play

import Foundation
import Security


func keyGen(keys : [String]) -> String
{
    func genProp(key : String) -> String
    {
        let typeName = key.substringToIndex(key.startIndex.successor()).uppercaseString + key.substringFromIndex(key.startIndex.successor()) + "Value"
        
        return "public var \(key) : \(typeName)? ;" +
        "private let \(key)Key = \\\"\\(\(key))\\\" ;;;"

    }
    
    
    
    let code = keys.map(genProp)
    
    return code.reduce("", combine: +)
}

func stringEnumGen(values : [String], typeName : String) -> String
{
    let header = "public enum \(typeName) : String {;"
    
    let footer = "};;"
    
    func genCase(val : String) -> String
    {
        return "case \(val) = \\\"\\(\(val))\\\";"
    }
    
    let cases = values.map(genCase)
    
    return header + cases.reduce("", combine: +) + footer
}


func reformatCode(code : String) -> String
{
    return code.stringByReplacingOccurrencesOfString(";", withString: "\n")
}

let attributeItemKeys = [
    "kSecAttrAccessible"
    ,"kSecAttrCreationDate"
    ,"kSecAttrModificationDate"
    ,"kSecAttrDescription"
    ,"kSecAttrComment"
    ,"kSecAttrCreator"
    ,"kSecAttrType"
    ,"kSecAttrLabel"
    ,"kSecAttrIsInvisible"
    ,"kSecAttrIsNegative"
    ,"kSecAttrAccount"
    ,"kSecAttrService"
    ,"kSecAttrGeneric"
    ,"kSecAttrSecurityDomain"
    ,"kSecAttrServer"
    ,"kSecAttrProtocol"
    ,"kSecAttrAuthenticationType"
    ,"kSecAttrPort"
    ,"kSecAttrPath"
    ,"kSecAttrSubject"
    ,"kSecAttrIssuer"
    ,"kSecAttrSerialNumber"
    ,"kSecAttrSubjectKeyID"
    ,"kSecAttrPublicKeyHash"
    ,"kSecAttrCertificateType"
    ,"kSecAttrCertificateEncoding"
    ,"kSecAttrKeyClass"
    ,"kSecAttrApplicationLabel"
    ,"kSecAttrIsPermanent"
    ,"kSecAttrApplicationTag"
    ,"kSecAttrKeyType"
    ,"kSecAttrKeySizeInBits"
    ,"kSecAttrEffectiveKeySize"
    ,"kSecAttrCanEncrypt"
    ,"kSecAttrCanDecrypt"
    ,"kSecAttrCanDerive"
    ,"kSecAttrCanSign"
    ,"kSecAttrCanVerify"
    ,"kSecAttrCanWrap"
    ,"kSecAttrCanUnwrap"
    ,"kSecAttrAccessGroup"];


let attributeItemKeysMetaCode = keyGen(attributeItemKeys)
println(attributeItemKeysMetaCode)

let attributeItemKeysCode = "public var kSecAttrAccessible : KSecAttrAccessibleValue? ;private let kSecAttrAccessibleKey = \"\(kSecAttrAccessible)\" ;;;public var kSecAttrCreationDate : KSecAttrCreationDateValue? ;private let kSecAttrCreationDateKey = \"\(kSecAttrCreationDate)\" ;;;public var kSecAttrModificationDate : KSecAttrModificationDateValue? ;private let kSecAttrModificationDateKey = \"\(kSecAttrModificationDate)\" ;;;public var kSecAttrDescription : KSecAttrDescriptionValue? ;private let kSecAttrDescriptionKey = \"\(kSecAttrDescription)\" ;;;public var kSecAttrComment : KSecAttrCommentValue? ;private let kSecAttrCommentKey = \"\(kSecAttrComment)\" ;;;public var kSecAttrCreator : KSecAttrCreatorValue? ;private let kSecAttrCreatorKey = \"\(kSecAttrCreator)\" ;;;public var kSecAttrType : KSecAttrTypeValue? ;private let kSecAttrTypeKey = \"\(kSecAttrType)\" ;;;public var kSecAttrLabel : KSecAttrLabelValue? ;private let kSecAttrLabelKey = \"\(kSecAttrLabel)\" ;;;public var kSecAttrIsInvisible : KSecAttrIsInvisibleValue? ;private let kSecAttrIsInvisibleKey = \"\(kSecAttrIsInvisible)\" ;;;public var kSecAttrIsNegative : KSecAttrIsNegativeValue? ;private let kSecAttrIsNegativeKey = \"\(kSecAttrIsNegative)\" ;;;public var kSecAttrAccount : KSecAttrAccountValue? ;private let kSecAttrAccountKey = \"\(kSecAttrAccount)\" ;;;public var kSecAttrService : KSecAttrServiceValue? ;private let kSecAttrServiceKey = \"\(kSecAttrService)\" ;;;public var kSecAttrGeneric : KSecAttrGenericValue? ;private let kSecAttrGenericKey = \"\(kSecAttrGeneric)\" ;;;public var kSecAttrSecurityDomain : KSecAttrSecurityDomainValue? ;private let kSecAttrSecurityDomainKey = \"\(kSecAttrSecurityDomain)\" ;;;public var kSecAttrServer : KSecAttrServerValue? ;private let kSecAttrServerKey = \"\(kSecAttrServer)\" ;;;public var kSecAttrProtocol : KSecAttrProtocolValue? ;private let kSecAttrProtocolKey = \"\(kSecAttrProtocol)\" ;;;public var kSecAttrAuthenticationType : KSecAttrAuthenticationTypeValue? ;private let kSecAttrAuthenticationTypeKey = \"\(kSecAttrAuthenticationType)\" ;;;public var kSecAttrPort : KSecAttrPortValue? ;private let kSecAttrPortKey = \"\(kSecAttrPort)\" ;;;public var kSecAttrPath : KSecAttrPathValue? ;private let kSecAttrPathKey = \"\(kSecAttrPath)\" ;;;public var kSecAttrSubject : KSecAttrSubjectValue? ;private let kSecAttrSubjectKey = \"\(kSecAttrSubject)\" ;;;public var kSecAttrIssuer : KSecAttrIssuerValue? ;private let kSecAttrIssuerKey = \"\(kSecAttrIssuer)\" ;;;public var kSecAttrSerialNumber : KSecAttrSerialNumberValue? ;private let kSecAttrSerialNumberKey = \"\(kSecAttrSerialNumber)\" ;;;public var kSecAttrSubjectKeyID : KSecAttrSubjectKeyIDValue? ;private let kSecAttrSubjectKeyIDKey = \"\(kSecAttrSubjectKeyID)\" ;;;public var kSecAttrPublicKeyHash : KSecAttrPublicKeyHashValue? ;private let kSecAttrPublicKeyHashKey = \"\(kSecAttrPublicKeyHash)\" ;;;public var kSecAttrCertificateType : KSecAttrCertificateTypeValue? ;private let kSecAttrCertificateTypeKey = \"\(kSecAttrCertificateType)\" ;;;public var kSecAttrCertificateEncoding : KSecAttrCertificateEncodingValue? ;private let kSecAttrCertificateEncodingKey = \"\(kSecAttrCertificateEncoding)\" ;;;public var kSecAttrKeyClass : KSecAttrKeyClassValue? ;private let kSecAttrKeyClassKey = \"\(kSecAttrKeyClass)\" ;;;public var kSecAttrApplicationLabel : KSecAttrApplicationLabelValue? ;private let kSecAttrApplicationLabelKey = \"\(kSecAttrApplicationLabel)\" ;;;public var kSecAttrIsPermanent : KSecAttrIsPermanentValue? ;private let kSecAttrIsPermanentKey = \"\(kSecAttrIsPermanent)\" ;;;public var kSecAttrApplicationTag : KSecAttrApplicationTagValue? ;private let kSecAttrApplicationTagKey = \"\(kSecAttrApplicationTag)\" ;;;public var kSecAttrKeyType : KSecAttrKeyTypeValue? ;private let kSecAttrKeyTypeKey = \"\(kSecAttrKeyType)\" ;;;public var kSecAttrKeySizeInBits : KSecAttrKeySizeInBitsValue? ;private let kSecAttrKeySizeInBitsKey = \"\(kSecAttrKeySizeInBits)\" ;;;public var kSecAttrEffectiveKeySize : KSecAttrEffectiveKeySizeValue? ;private let kSecAttrEffectiveKeySizeKey = \"\(kSecAttrEffectiveKeySize)\" ;;;public var kSecAttrCanEncrypt : KSecAttrCanEncryptValue? ;private let kSecAttrCanEncryptKey = \"\(kSecAttrCanEncrypt)\" ;;;public var kSecAttrCanDecrypt : KSecAttrCanDecryptValue? ;private let kSecAttrCanDecryptKey = \"\(kSecAttrCanDecrypt)\" ;;;public var kSecAttrCanDerive : KSecAttrCanDeriveValue? ;private let kSecAttrCanDeriveKey = \"\(kSecAttrCanDerive)\" ;;;public var kSecAttrCanSign : KSecAttrCanSignValue? ;private let kSecAttrCanSignKey = \"\(kSecAttrCanSign)\" ;;;public var kSecAttrCanVerify : KSecAttrCanVerifyValue? ;private let kSecAttrCanVerifyKey = \"\(kSecAttrCanVerify)\" ;;;public var kSecAttrCanWrap : KSecAttrCanWrapValue? ;private let kSecAttrCanWrapKey = \"\(kSecAttrCanWrap)\" ;;;public var kSecAttrCanUnwrap : KSecAttrCanUnwrapValue? ;private let kSecAttrCanUnwrapKey = \"\(kSecAttrCanUnwrap)\" ;;;"

println(reformatCode(attributeItemKeysCode))


let accessibilityValues = ["kSecAttrAccessibleWhenUnlocked",
    "kSecAttrAccessibleAfterFirstUnlock",
    "kSecAttrAccessibleAlways",
    "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
    "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
    "kSecAttrAccessibleAlwaysThisDeviceOnly"]

let accessibilityValuesMetaCode = stringEnumGen(accessibilityValues,"KSecAttrAccessibleValue")
println("\n\n\n\n" + accessibilityValuesMetaCode)
let accessibilityValuesCode = "public enum KSecAttrAccessibleValue : String {;case kSecAttrAccessibleWhenUnlocked = \"\(kSecAttrAccessibleWhenUnlocked)\";case kSecAttrAccessibleAfterFirstUnlock = \"\(kSecAttrAccessibleAfterFirstUnlock)\";case kSecAttrAccessibleAlways = \"\(kSecAttrAccessibleAlways)\";case kSecAttrAccessibleWhenUnlockedThisDeviceOnly = \"\(kSecAttrAccessibleWhenUnlockedThisDeviceOnly)\";case kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = \"\(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)\";case kSecAttrAccessibleAlwaysThisDeviceOnly = \"\(kSecAttrAccessibleAlwaysThisDeviceOnly)\";};;"

println(reformatCode(accessibilityValuesCode))


let attrProtocolValues = ["kSecAttrProtocolFTP",
"kSecAttrProtocolFTPAccount",
"kSecAttrProtocolHTTP",
"kSecAttrProtocolIRC",
"kSecAttrProtocolNNTP",
"kSecAttrProtocolPOP3",
"kSecAttrProtocolSMTP",
"kSecAttrProtocolSOCKS",
"kSecAttrProtocolIMAP",
"kSecAttrProtocolLDAP",
"kSecAttrProtocolAppleTalk",
"kSecAttrProtocolAFP",
"kSecAttrProtocolTelnet",
"kSecAttrProtocolSSH",
"kSecAttrProtocolFTPS",
"kSecAttrProtocolHTTPS",
"kSecAttrProtocolHTTPProxy",
"kSecAttrProtocolHTTPSProxy",
"kSecAttrProtocolFTPProxy",
"kSecAttrProtocolSMB",
"kSecAttrProtocolRTSP",
"kSecAttrProtocolRTSPProxy",
"kSecAttrProtocolDAAP",
"kSecAttrProtocolEPPC",
"kSecAttrProtocolIPP",
"kSecAttrProtocolNNTPS",
"kSecAttrProtocolLDAPS",
"kSecAttrProtocolTelnetS",
"kSecAttrProtocolIMAPS",
"kSecAttrProtocolIRCS",
"kSecAttrProtocolPOP3S"]
let attrProtocolValuesMetaCode = stringEnumGen(attrProtocolValues,"KSecAttrProtocolValue")

let attrProtocolValuesCode = "public enum KSecAttrProtocolValue : String {;case kSecAttrProtocolFTP = \"\(kSecAttrProtocolFTP)\";case kSecAttrProtocolFTPAccount = \"\(kSecAttrProtocolFTPAccount)\";case kSecAttrProtocolHTTP = \"\(kSecAttrProtocolHTTP)\";case kSecAttrProtocolIRC = \"\(kSecAttrProtocolIRC)\";case kSecAttrProtocolNNTP = \"\(kSecAttrProtocolNNTP)\";case kSecAttrProtocolPOP3 = \"\(kSecAttrProtocolPOP3)\";case kSecAttrProtocolSMTP = \"\(kSecAttrProtocolSMTP)\";case kSecAttrProtocolSOCKS = \"\(kSecAttrProtocolSOCKS)\";case kSecAttrProtocolIMAP = \"\(kSecAttrProtocolIMAP)\";case kSecAttrProtocolLDAP = \"\(kSecAttrProtocolLDAP)\";case kSecAttrProtocolAppleTalk = \"\(kSecAttrProtocolAppleTalk)\";case kSecAttrProtocolAFP = \"\(kSecAttrProtocolAFP)\";case kSecAttrProtocolTelnet = \"\(kSecAttrProtocolTelnet)\";case kSecAttrProtocolSSH = \"\(kSecAttrProtocolSSH)\";case kSecAttrProtocolFTPS = \"\(kSecAttrProtocolFTPS)\";case kSecAttrProtocolHTTPS = \"\(kSecAttrProtocolHTTPS)\";case kSecAttrProtocolHTTPProxy = \"\(kSecAttrProtocolHTTPProxy)\";case kSecAttrProtocolHTTPSProxy = \"\(kSecAttrProtocolHTTPSProxy)\";case kSecAttrProtocolFTPProxy = \"\(kSecAttrProtocolFTPProxy)\";case kSecAttrProtocolSMB = \"\(kSecAttrProtocolSMB)\";case kSecAttrProtocolRTSP = \"\(kSecAttrProtocolRTSP)\";case kSecAttrProtocolRTSPProxy = \"\(kSecAttrProtocolRTSPProxy)\";case kSecAttrProtocolDAAP = \"\(kSecAttrProtocolDAAP)\";case kSecAttrProtocolEPPC = \"\(kSecAttrProtocolEPPC)\";case kSecAttrProtocolIPP = \"\(kSecAttrProtocolIPP)\";case kSecAttrProtocolNNTPS = \"\(kSecAttrProtocolNNTPS)\";case kSecAttrProtocolLDAPS = \"\(kSecAttrProtocolLDAPS)\";case kSecAttrProtocolTelnetS = \"\(kSecAttrProtocolTelnetS)\";case kSecAttrProtocolIMAPS = \"\(kSecAttrProtocolIMAPS)\";case kSecAttrProtocolIRCS = \"\(kSecAttrProtocolIRCS)\";case kSecAttrProtocolPOP3S = \"\(kSecAttrProtocolPOP3S)\";};;"

println(reformatCode(attrProtocolValuesCode))

let authenticationType = ["kSecAttrAuthenticationTypeNTLM",
    "kSecAttrAuthenticationTypeMSN",
    "kSecAttrAuthenticationTypeDPA",
    "kSecAttrAuthenticationTypeRPA",
    "kSecAttrAuthenticationTypeHTTPBasic",
    "kSecAttrAuthenticationTypeHTTPDigest",
    "kSecAttrAuthenticationTypeHTMLForm",
    "kSecAttrAuthenticationTypeDefault"]
let authenticationTypeMetaCode = stringEnumGen(authenticationType,"KSecAttrAuthenticationTypeValue")

let authenticationTypeCode = "public enum KSecAttrAuthenticationTypeValue : String {;case kSecAttrAuthenticationTypeNTLM = \"\(kSecAttrAuthenticationTypeNTLM)\";case kSecAttrAuthenticationTypeMSN = \"\(kSecAttrAuthenticationTypeMSN)\";case kSecAttrAuthenticationTypeDPA = \"\(kSecAttrAuthenticationTypeDPA)\";case kSecAttrAuthenticationTypeRPA = \"\(kSecAttrAuthenticationTypeRPA)\";case kSecAttrAuthenticationTypeHTTPBasic = \"\(kSecAttrAuthenticationTypeHTTPBasic)\";case kSecAttrAuthenticationTypeHTTPDigest = \"\(kSecAttrAuthenticationTypeHTTPDigest)\";case kSecAttrAuthenticationTypeHTMLForm = \"\(kSecAttrAuthenticationTypeHTMLForm)\";case kSecAttrAuthenticationTypeDefault = \"\(kSecAttrAuthenticationTypeDefault)\";};;"
println(reformatCode(authenticationTypeCode))

let keyClassValues = ["kSecAttrKeyClassPublic","kSecAttrKeyClassPrivate", "kSecAttrKeyClassSymmetric"]
let keyClassValuesMetaCode = stringEnumGen(keyClassValues,"KSecAttrKeyClassValue")
let keyClassValuesCode = "public enum KSecAttrKeyClassValue : String {;case kSecAttrKeyClassPublic = \"\(kSecAttrKeyClassPublic)\";case kSecAttrKeyClassPrivate = \"\(kSecAttrKeyClassPrivate)\";case kSecAttrKeyClassSymmetric = \"\(kSecAttrKeyClassSymmetric)\";};;"
println(reformatCode(keyClassValuesCode))

