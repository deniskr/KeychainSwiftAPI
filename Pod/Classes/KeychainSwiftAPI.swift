//
//  Keychain.swift
//  KeychainSwiftAPI
//
//  Created by Denis Krivitski on 22/7/14.
//  Copyright (c) 2014 Checkmarx. All rights reserved.
//

import Foundation
import Security

public func == (left:Keychain.ResultCode, right:Keychain.ResultCode) -> Bool
{
    return left.toRaw() == right.toRaw()
}

public func != (left:Keychain.ResultCode, right:Keychain.ResultCode) -> Bool {
    return !(left == right)
}

public class Keychain
{
    /**
    A Swift style wrapper of OSStatus result codes that can be returned from KeyChain functions.
    */

    public enum ResultCode : Printable {
        case errSecSuccess                //  = 0        // No error.
        case errSecUnimplemented          //  = -4       // Function or operation not implemented.
        case errSecParam                  //  = -50      // One or more parameters passed to the function were not valid.
        case errSecAllocate               //  = -108     // Failed to allocate memory.
        case errSecNotAvailable           //  = -25291   // No trust results are available.
        case errSecAuthFailed             //  = -25293   // Authorization/Authentication failed.
        case errSecDuplicateItem          //  = -25299   // The item already exists.
        case errSecItemNotFound           //  = -25300   // The item cannot be found.
        case errSecInteractionNotAllowed  //  = -25308   // Interaction with the Security Server is not allowed.
        case errSecDecode                 //  = -26275   // Unable to decode the provided data.
        case other(OSStatus)
        
        public func toRaw() -> OSStatus
        {
            switch self {
            case errSecSuccess:                 return  0
            case errSecUnimplemented:           return -4
            case errSecParam:                   return -50
            case errSecAllocate:                return -108
            case errSecNotAvailable:            return -25291
            case errSecAuthFailed:              return -25293
            case errSecDuplicateItem:           return -25299
            case errSecItemNotFound:            return -25300
            case errSecInteractionNotAllowed:   return -25308
            case errSecDecode:                  return -26275
            case let other(status):             return status
            }
        }
        
        public static func fromRaw(status : OSStatus) -> ResultCode
        {
            switch status {
                
            case    0 	 : return ResultCode.errSecSuccess
            case   -4 	 : return ResultCode.errSecUnimplemented
            case   -50 	 : return ResultCode.errSecParam
            case   -108  : return ResultCode.errSecAllocate
            case   -25291: return ResultCode.errSecNotAvailable
            case   -25293: return ResultCode.errSecAuthFailed
            case   -25299: return ResultCode.errSecDuplicateItem
            case   -25300: return ResultCode.errSecItemNotFound
            case   -25308: return ResultCode.errSecInteractionNotAllowed
            case   -26275: return ResultCode.errSecDecode
                
            default: return ResultCode.other(status)
            }
        }
        
        public var description: String { get {
            switch self {
            case errSecSuccess:                 return "Success"
            case errSecUnimplemented:           return "Function or operation not implemented."
            case errSecParam:                   return "One or more parameters passed to the function were not valid."
            case errSecAllocate:                return "Failed to allocate memory."
            case errSecNotAvailable:            return "No trust results are available."
            case errSecAuthFailed:              return "Authorization/Authentication failed."
            case errSecDuplicateItem:           return "The item already exists."
            case errSecItemNotFound:            return "The item cannot be found."
            case errSecInteractionNotAllowed:   return "Interaction with the Security Server is not allowed."
            case errSecDecode:                  return "Unable to decode the provided data."
            case let other(status):             return "Error code: \(status)"
            }
        }}
        
        
    }
    
    /**

    A Swift style wrapper of KeyChain attributes dictionary. Class property names correspond to attribute keys,
    property values correspond to attribute values. All properties are of optional type. When a prerty is nil, 
    the corresponding key-value pair will not be added to the attributes dictionary.
    
    For a description of key-value pairs see the documentation of Keychain API.
    */

    public class Query {
        public init(){}
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Item class
        /////////////////////////////////////////////////////////////////////////////////////////////////////////

        public var kSecClass : KSecClassValue?
        private let kSecClassKey = "class"
        public enum KSecClassValue : String {
            
            case kSecClassGenericPassword   = "genp"
            case kSecClassInternetPassword  = "inet"
            case kSecClassCertificate       = "cert"
            case kSecClassKey               = "keys"
            case kSecClassIdentity          = "idnt"
            
        }
        private func kSecClassAddToDic(dic : NSMutableDictionary) {
            if let v = kSecClass {
                dic.setObject(v.rawValue, forKey: kSecClassKey)
            }
        }

        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Return data type
        /////////////////////////////////////////////////////////////////////////////////////////////////////////

        
        public var kSecReturnData : Bool = false
        private let kSecReturnDataKey = "r_Data"
        private func kSecReturnDataAddToDic(dic : NSMutableDictionary) {
            if kSecReturnData {
                dic.setObject(NSNumber(bool: true), forKey: kSecReturnDataKey)
            }
        }

        public var kSecReturnAttributes : Bool = false
        private let kSecReturnAttributesKey = "r_Attributes"
        private func kSecReturnAttributesAddToDic(dic : NSMutableDictionary) {
            if kSecReturnAttributes {
                dic.setObject(NSNumber(bool: true), forKey: kSecReturnAttributesKey)
            }
        }

        public var kSecReturnRef : Bool = false
        private let kSecReturnRefKey = "r_Ref"
        private func kSecReturnRefAddToDic(dic : NSMutableDictionary) {
            if kSecReturnRef {
                dic.setObject(NSNumber(bool: true), forKey: kSecReturnRefKey)
            }
        }

        public var kSecReturnPersistentRef : Bool = false
        private let kSecReturnPersistentRefKey = "r_PersistentRef"
        private func kSecReturnPersistentRefAddToDic(dic : NSMutableDictionary) {
            if kSecReturnPersistentRef {
                dic.setObject(NSNumber(bool: true), forKey: kSecReturnPersistentRefKey)
            }
        }

        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Value
        /////////////////////////////////////////////////////////////////////////////////////////////////////////

        
        public var kSecValueData : NSData?
        private let kSecValueDataKey = "v_Data"
        private func kSecValueDataAddToDic(dic : NSMutableDictionary) {
            if let v = kSecValueData {
                dic.setObject(v, forKey: kSecValueDataKey)
            }
        }
        
        
        public var kSecValueRef : KSecValueRefValue?
        private let kSecValueRefKey = "v_Ref"
        public enum KSecValueRefValue {
            case Key(SecKeyRef)
            case Certificate(SecCertificateRef)
            case Identity(SecIdentityRef)
        }
        private func kSecValueRefAddToDic(dic : NSMutableDictionary) {
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
        }

        
        public var kSecValuePersistentRef : NSData?
        private let kSecValuePersistentRefKey = "v_PersistentRef"
        private func kSecValuePersistentRefAddToDic(dic : NSMutableDictionary) {
            if let v = kSecValuePersistentRef {
                dic.setObject(v, forKey: kSecValuePersistentRefKey)
            }
        }
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Attributes
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
       
        public  var kSecAttrAccessible : KSecAttrAccessibleValue?
        private let kSecAttrAccessibleKey = "pdmn"
        public enum KSecAttrAccessibleValue : String {
            case kSecAttrAccessibleWhenUnlocked = "ak"
            case kSecAttrAccessibleAfterFirstUnlock = "ck"
            case kSecAttrAccessibleAlways = "dk"
            case kSecAttrAccessibleWhenUnlockedThisDeviceOnly = "aku"
            case kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = "cku"
            case kSecAttrAccessibleAlwaysThisDeviceOnly = "dku"
        }
        private func kSecAttrAccessibleAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrAccessible {
                dic.setObject(v.rawValue, forKey: kSecAttrAccessibleKey)
            }
        }
        
        
        public   var kSecAttrCreationDate : NSDate?
        private  let kSecAttrCreationDateKey = "cdat"
        private func kSecAttrCreationDateAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrCreationDate {
                dic.setObject(v, forKey: kSecAttrCreationDateKey)
            }
        }
        
        public   var kSecAttrModificationDate : NSDate?
        private  let kSecAttrModificationDateKey = "mdat"
        private func kSecAttrModificationDateAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrModificationDate {
                dic.setObject(v, forKey: kSecAttrModificationDateKey)
            }
        }
        
        public var kSecAttrDescription : String?
        private let kSecAttrDescriptionKey = "desc"
        private func kSecAttrDescriptionAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrDescription {
                dic.setObject(v, forKey: kSecAttrDescriptionKey)
            }
        }
        
        public var kSecAttrComment : String?
        private let kSecAttrCommentKey = "icmt"
        private func kSecAttrCommentAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrComment {
                dic.setObject(v, forKey: kSecAttrCommentKey)
            }
        }
        
        public var kSecAttrCreator : UInt32? // NSNumber with unsigned integer
        private let kSecAttrCreatorKey = "crtr"
        private func kSecAttrCreatorAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrCreator {
                dic.setObject(NSNumber(unsignedInt: v), forKey: kSecAttrCreatorKey)
            }
        }
        
        public   var kSecAttrType : UInt32? // NSNumber with unsigned integer
        private  let kSecAttrTypeKey = "type"
        private func kSecAttrTypeAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrType {
                dic.setObject(NSNumber(unsignedInt: v), forKey: kSecAttrTypeKey)
            }
        }
        
        public var kSecAttrLabel : String?
        private let kSecAttrLabelKey = "labl"
        private func kSecAttrLabelAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrLabel {
                dic.setObject(v, forKey: kSecAttrLabelKey)
            }
        }
        
        public var kSecAttrIsInvisible : Bool = false // NSNumber with bool
        private let kSecAttrIsInvisibleKey = "invi"
        private func kSecAttrIsInvisibleAddToDic(dic : NSMutableDictionary) {
            if kSecAttrIsInvisible {
                dic.setObject(NSNumber(bool: true), forKey: kSecAttrIsInvisibleKey)
            }
        }
        
        public var kSecAttrIsNegative : Bool = false // NSNumber with bool
        private let kSecAttrIsNegativeKey = "nega"
        private func kSecAttrIsNegativeAddToDic(dic : NSMutableDictionary) {
            if kSecAttrIsNegative {
                dic.setObject(NSNumber(bool: true), forKey: kSecAttrIsNegativeKey)
            }
        }

        
        public var kSecAttrAccount : String?
        private let kSecAttrAccountKey = "acct"
        private func kSecAttrAccountAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrAccount {
                dic.setObject(v, forKey: kSecAttrAccountKey)
            }
        }
        
        public var kSecAttrService : String?
        private let kSecAttrServiceKey = "svce"
         private func kSecAttrServiceAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrService {
                dic.setObject(v, forKey: kSecAttrServiceKey)
            }
        }
        
        public var kSecAttrGeneric : NSData?
        private let kSecAttrGenericKey = "gena"
         private func kSecAttrGenericAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrGeneric {
                dic.setObject(v, forKey: kSecAttrGenericKey)
            }
        }
        
        public var kSecAttrSecurityDomain : String?
        private let kSecAttrSecurityDomainKey = "sdmn"
         private func kSecAttrSecurityDomainAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrSecurityDomain {
                dic.setObject(v, forKey: kSecAttrSecurityDomainKey)
            }
        }
        
        public var kSecAttrServer : String?
        private let kSecAttrServerKey = "srvr"
         private func kSecAttrServerAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrServer {
                dic.setObject(v, forKey: kSecAttrServerKey)
            }
        }
        
        public var kSecAttrProtocol : KSecAttrProtocolValue?
        private let kSecAttrProtocolKey = "ptcl"
        public enum KSecAttrProtocolValue : String {
            case kSecAttrProtocolFTP = "ftp "
            case kSecAttrProtocolFTPAccount = "ftpa"
            case kSecAttrProtocolHTTP = "http"
            case kSecAttrProtocolIRC = "irc "
            case kSecAttrProtocolNNTP = "nntp"
            case kSecAttrProtocolPOP3 = "pop3"
            case kSecAttrProtocolSMTP = "smtp"
            case kSecAttrProtocolSOCKS = "sox "
            case kSecAttrProtocolIMAP = "imap"
            case kSecAttrProtocolLDAP = "ldap"
            case kSecAttrProtocolAppleTalk = "atlk"
            case kSecAttrProtocolAFP = "afp "
            case kSecAttrProtocolTelnet = "teln"
            case kSecAttrProtocolSSH = "ssh "
            case kSecAttrProtocolFTPS = "ftps"
            case kSecAttrProtocolHTTPS = "htps"
            case kSecAttrProtocolHTTPProxy = "htpx"
            case kSecAttrProtocolHTTPSProxy = "htsx"
            case kSecAttrProtocolFTPProxy = "ftpx"
            case kSecAttrProtocolSMB = "smb "
            case kSecAttrProtocolRTSP = "rtsp"
            case kSecAttrProtocolRTSPProxy = "rtsx"
            case kSecAttrProtocolDAAP = "daap"
            case kSecAttrProtocolEPPC = "eppc"
            case kSecAttrProtocolIPP = "ipp "
            case kSecAttrProtocolNNTPS = "ntps"
            case kSecAttrProtocolLDAPS = "ldps"
            case kSecAttrProtocolTelnetS = "tels"
            case kSecAttrProtocolIMAPS = "imps"
            case kSecAttrProtocolIRCS = "ircs"
            case kSecAttrProtocolPOP3S = "pops"
        }
        private func kSecAttrProtocolAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrProtocol {
                dic.setObject(v.rawValue, forKey: kSecAttrProtocolKey)
            }
        }

        
        
        public var kSecAttrAuthenticationType : KSecAttrAuthenticationTypeValue?
        private let kSecAttrAuthenticationTypeKey = "atyp"
        public enum KSecAttrAuthenticationTypeValue : String {
            case kSecAttrAuthenticationTypeNTLM = "ntlm"
            case kSecAttrAuthenticationTypeMSN = "msna"
            case kSecAttrAuthenticationTypeDPA = "dpaa"
            case kSecAttrAuthenticationTypeRPA = "rpaa"
            case kSecAttrAuthenticationTypeHTTPBasic = "http"
            case kSecAttrAuthenticationTypeHTTPDigest = "httd"
            case kSecAttrAuthenticationTypeHTMLForm = "form"
            case kSecAttrAuthenticationTypeDefault = "dflt"
        }
        private func kSecAttrAuthenticationTypeAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrAuthenticationType {
                dic.setObject(v.rawValue, forKey: kSecAttrAuthenticationTypeKey)
            }
        }

        
        public var kSecAttrPort : UInt32? // NSNumber unsigned
        private let kSecAttrPortKey = "port"
        private func kSecAttrPortAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrPort {
                dic.setObject(NSNumber(unsignedInt: v), forKey: kSecAttrPortKey)
            }
        }
        
        public var kSecAttrPath : String?
        private let kSecAttrPathKey = "path"
         private func kSecAttrPathAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrPath {
                dic.setObject(v, forKey: kSecAttrPathKey)
            }
        }
        
        public var kSecAttrSubject : NSData?
        private let kSecAttrSubjectKey = "subj"
         private func kSecAttrSubjectAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrSubject {
                dic.setObject(v, forKey: kSecAttrSubjectKey)
            }
        }
        
        public var kSecAttrIssuer : NSData?
        private let kSecAttrIssuerKey = "issr"
         private func kSecAttrIssuerAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrIssuer {
                dic.setObject(v, forKey: kSecAttrIssuerKey)
            }
        }
        
        public var kSecAttrSerialNumber : NSData?
        private let kSecAttrSerialNumberKey = "slnr"
         private func kSecAttrSerialNumberAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrSerialNumber {
                dic.setObject(v, forKey: kSecAttrSerialNumberKey)
            }
        }
        
        public var kSecAttrSubjectKeyID : NSData?
        private let kSecAttrSubjectKeyIDKey = "skid"
         private func kSecAttrSubjectKeyIDAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrSubjectKeyID {
                dic.setObject(v, forKey: kSecAttrSubjectKeyIDKey)
            }
        }
        
        public var kSecAttrPublicKeyHash : NSData?
        private let kSecAttrPublicKeyHashKey = "pkhh"
         private func kSecAttrPublicKeyHashAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrPublicKeyHash {
                dic.setObject(v, forKey: kSecAttrPublicKeyHashKey)
            }
        }
        
        public var kSecAttrCertificateType : KSecAttrCertificateTypeValue? // NSSNumber
        private let kSecAttrCertificateTypeKey = "ctyp"
        public enum KSecAttrCertificateTypeValue {
            case Standard(CSSM_CERT_TYPE)
            case Custom(UInt32)
        }
        public enum CSSM_CERT_TYPE : UInt32 { // CSSM_CERT_TYPE
            case CSSM_CERT_UNKNOWN =					0x00
            case CSSM_CERT_X_509v1 =					0x01
            case CSSM_CERT_X_509v2 =					0x02
            case CSSM_CERT_X_509v3 =					0x03
            case CSSM_CERT_PGP =						0x04
            case CSSM_CERT_SPKI =                       0x05
            case CSSM_CERT_SDSIv1 =                     0x06
            case CSSM_CERT_Intel =                      0x08
            case CSSM_CERT_X_509_ATTRIBUTE =			0x09 /* X.509 attribute cert */
            case CSSM_CERT_X9_ATTRIBUTE =               0x0A /* X9 attribute cert */
            case CSSM_CERT_TUPLE =                      0x0B
            case CSSM_CERT_ACL_ENTRY =                  0x0C
            case CSSM_CERT_MULTIPLE =                   0x7FFE
            case CSSM_CERT_LAST =                       0x7FFF
            /* Applications wishing to define their own custom certificate
            type should define and publicly document a uint32 value greater
            than the CSSM_CL_CUSTOM_CERT_TYPE */
            case CSSM_CL_CUSTOM_CERT_TYPE =             0x08000
        }
        private func kSecAttrCertificateTypeAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrCertificateType {
                switch v {
                case let .Standard(val):
                        dic.setObject(NSNumber(unsignedInt: val.rawValue), forKey: kSecAttrCertificateTypeKey)
                case let .Custom(val):
                        dic.setObject(NSNumber(unsignedInt: val), forKey: kSecAttrCertificateTypeKey)
                }
            }
        }
        
        public var kSecAttrCertificateEncoding : KSecAttrCertificateEncodingValue? // NSNumber
        private let kSecAttrCertificateEncodingKey = "cenc"
        public enum KSecAttrCertificateEncodingValue {
            case Standard(CSSM_CERT_ENCODING)
            case Custom(UInt32)
        }
        public enum CSSM_CERT_ENCODING : UInt32 {
            case CSSM_CERT_ENCODING_UNKNOWN =		0x00
            case CSSM_CERT_ENCODING_CUSTOM =		0x01
            case CSSM_CERT_ENCODING_BER =			0x02
            case CSSM_CERT_ENCODING_DER =			0x03
            case CSSM_CERT_ENCODING_NDR =			0x04
            case CSSM_CERT_ENCODING_SEXPR =			0x05
            case CSSM_CERT_ENCODING_PGP =			0x06
            case CSSM_CERT_ENCODING_MULTIPLE =		0x7FFE
            case CSSM_CERT_ENCODING_LAST =			0x7FFF
            /* Applications wishing to define their own custom certificate
            encoding should create a uint32 value greater than the
            CSSM_CL_CUSTOM_CERT_ENCODING */
            case CSSM_CL_CUSTOM_CERT_ENCODING =		0x8000
        }
        private func kSecAttrCertificateEncodingAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrCertificateEncoding {
                switch v {
                case let .Standard(val):
                    dic.setObject(NSNumber(unsignedInt: val.rawValue), forKey: kSecAttrCertificateEncodingKey)
                case let .Custom(val):
                    dic.setObject(NSNumber(unsignedInt: val), forKey: kSecAttrCertificateEncodingKey)
                }
            }
        }

        
        
        public var kSecAttrKeyClass : KSecAttrKeyClassValue?
        private let kSecAttrKeyClassKey = "kcls"
        public enum KSecAttrKeyClassValue : String {
            case kSecAttrKeyClassPublic = "0"
            case kSecAttrKeyClassPrivate = "1"
            case kSecAttrKeyClassSymmetric = "2"
        }
        private func kSecAttrKeyClassAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrKeyClass {
                dic.setObject(v.rawValue, forKey: kSecAttrKeyClassKey)
            }
        }
       
        
        public var kSecAttrApplicationLabel : String?
        private let kSecAttrApplicationLabelKey = "klbl"
        private func kSecAttrApplicationLabelAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrApplicationLabel {
                dic.setObject(v, forKey: kSecAttrApplicationLabelKey)
            }
        }
        
        public var kSecAttrIsPermanent : Bool? // NSNumber bool
        private let kSecAttrIsPermanentKey = "perm"
        private func kSecAttrIsPermanentAddToDic(dic : NSMutableDictionary) {
            if (kSecAttrIsPermanent != nil && kSecAttrIsPermanent!) {
                dic.setObject(NSNumber(bool: true), forKey: kSecAttrIsPermanentKey)
            }
        }

        
        public var kSecAttrApplicationTag : NSData?
        private let kSecAttrApplicationTagKey = "atag"
        private func kSecAttrApplicationTagAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrApplicationTag {
                dic.setObject(v, forKey: kSecAttrApplicationTagKey)
            }
        }
        
        public var kSecAttrKeyType : KSecAttrKeyTypeValue? // NSNumber, in practice it is CFString
        private let kSecAttrKeyTypeKey = "type"
        public enum KSecAttrKeyTypeValue {
            case Standard(CSSM_ALGORITHMS)
            case Custom(UInt32)
        }
        public enum CSSM_ALGORITHMS : UInt32 {
            case CSSM_ALGID_NONE =					0
            case CSSM_ALGID_CUSTOM =				1
            case CSSM_ALGID_DH =					2
            case CSSM_ALGID_PH =					3
            case CSSM_ALGID_KEA =					4
            case CSSM_ALGID_MD2 =					5
            case CSSM_ALGID_MD4 =					6
            case CSSM_ALGID_MD5 =					7
            case CSSM_ALGID_SHA1 =					8
            case CSSM_ALGID_NHASH =					9
            case CSSM_ALGID_HAVAL =					10
            case CSSM_ALGID_RIPEMD =				11
            case CSSM_ALGID_IBCHASH =				12
            case CSSM_ALGID_RIPEMAC =				13
            case CSSM_ALGID_DES =					14
            case CSSM_ALGID_DESX =					15
            case CSSM_ALGID_RDES =					16
            case CSSM_ALGID_3DES_3KEY_EDE =			17
            case CSSM_ALGID_3DES_2KEY_EDE =			18
            case CSSM_ALGID_3DES_1KEY_EEE =			19
            //case CSSM_ALGID_3DES_3KEY =           	CSSM_ALGID_3DES_3KEY_EDE
            case CSSM_ALGID_3DES_3KEY_EEE =       	20
            //case CSSM_ALGID_3DES_2KEY =           	CSSM_ALGID_3DES_2KEY_EDE
            case CSSM_ALGID_3DES_2KEY_EEE =       	21
            //case CSSM_ALGID_3DES_1KEY =				CSSM_ALGID_3DES_3KEY_EEE
            case CSSM_ALGID_IDEA =					22
            case CSSM_ALGID_RC2 =					23
            case CSSM_ALGID_RC5 =					24
            case CSSM_ALGID_RC4 =					25
            case CSSM_ALGID_SEAL =					26
            case CSSM_ALGID_CAST =					27
            case CSSM_ALGID_BLOWFISH =				28
            case CSSM_ALGID_SKIPJACK =				29
            case CSSM_ALGID_LUCIFER =				30
            case CSSM_ALGID_MADRYGA =				31
            case CSSM_ALGID_FEAL =					32
            case CSSM_ALGID_REDOC =					33
            case CSSM_ALGID_REDOC3 =				34
            case CSSM_ALGID_LOKI =					35
            case CSSM_ALGID_KHUFU =					36
            case CSSM_ALGID_KHAFRE =				37
            case CSSM_ALGID_MMB =					38
            case CSSM_ALGID_GOST =					39
            case CSSM_ALGID_SAFER =					40
            case CSSM_ALGID_CRAB =					41
            case CSSM_ALGID_RSA =					42
            case CSSM_ALGID_DSA =					43
            case CSSM_ALGID_MD5WithRSA =			44
            case CSSM_ALGID_MD2WithRSA =			45
            case CSSM_ALGID_ElGamal =				46
            case CSSM_ALGID_MD2Random =				47
            case CSSM_ALGID_MD5Random =				48
            case CSSM_ALGID_SHARandom =				49
            case CSSM_ALGID_DESRandom =				50
            case CSSM_ALGID_SHA1WithRSA =			51
            case CSSM_ALGID_CDMF =					52
            case CSSM_ALGID_CAST3 =					53
            case CSSM_ALGID_CAST5 =					54
            case CSSM_ALGID_GenericSecret =			55
            case CSSM_ALGID_ConcatBaseAndKey =		56
            case CSSM_ALGID_ConcatKeyAndBase =		57
            case CSSM_ALGID_ConcatBaseAndData =		58
            case CSSM_ALGID_ConcatDataAndBase =		59
            case CSSM_ALGID_XORBaseAndData =		60
            case CSSM_ALGID_ExtractFromKey =		61
            case CSSM_ALGID_SSL3PreMasterGen =		62
            case CSSM_ALGID_SSL3MasterDerive =		63
            case CSSM_ALGID_SSL3KeyAndMacDerive =	64
            case CSSM_ALGID_SSL3MD5_MAC =			65
            case CSSM_ALGID_SSL3SHA1_MAC =			66
            case CSSM_ALGID_PKCS5_PBKDF1_MD5 =		67
            case CSSM_ALGID_PKCS5_PBKDF1_MD2 =		68
            case CSSM_ALGID_PKCS5_PBKDF1_SHA1 =		69
            case CSSM_ALGID_WrapLynks =				70
            case CSSM_ALGID_WrapSET_OAEP =			71
            case CSSM_ALGID_BATON =					72
            case CSSM_ALGID_ECDSA =					73
            case CSSM_ALGID_MAYFLY =				74
            case CSSM_ALGID_JUNIPER =				75
            case CSSM_ALGID_FASTHASH =				76
            case CSSM_ALGID_3DES =					77
            case CSSM_ALGID_SSL3MD5 =				78
            case CSSM_ALGID_SSL3SHA1 =				79
            case CSSM_ALGID_FortezzaTimestamp =		80
            case CSSM_ALGID_SHA1WithDSA =			81
            case CSSM_ALGID_SHA1WithECDSA =			82
            case CSSM_ALGID_DSA_BSAFE =				83
            case CSSM_ALGID_ECDH =					84
            case CSSM_ALGID_ECMQV =					85
            case CSSM_ALGID_PKCS12_SHA1_PBE =		86
            case CSSM_ALGID_ECNRA =					87
            case CSSM_ALGID_SHA1WithECNRA =			88
            case CSSM_ALGID_ECES =					89
            case CSSM_ALGID_ECAES =					90
            case CSSM_ALGID_SHA1HMAC =				91
            case CSSM_ALGID_FIPS186Random =			92
            case CSSM_ALGID_ECC =					93
            case CSSM_ALGID_MQV =					94
            case CSSM_ALGID_NRA =					95
            case CSSM_ALGID_IntelPlatformRandom =	96
            case CSSM_ALGID_UTC =					97
            case CSSM_ALGID_HAVAL3 =				98
            case CSSM_ALGID_HAVAL4 =				99
            case CSSM_ALGID_HAVAL5 =				100
            case CSSM_ALGID_TIGER =					101
            case CSSM_ALGID_MD5HMAC =				102
            case CSSM_ALGID_PKCS5_PBKDF2 = 			103
            case CSSM_ALGID_RUNNING_COUNTER =		104
            case CSSM_ALGID_LAST =					0x7FFFFFFF
            /* All algorithms IDs that are vendor specific and not
            part of the CSSM specification should be defined relative
            to CSSM_ALGID_VENDOR_DEFINED. */
            case CSSM_ALGID_VENDOR_DEFINED =		0x80000000
        }
        private func kSecAttrKeyTypeAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrKeyType {
                switch v {
                case let .Standard(val):
                        dic.setObject(NSNumber(unsignedInt: val.rawValue), forKey: kSecAttrKeyTypeKey)
                case let .Custom(val):
                        dic.setObject(NSNumber(unsignedInt: val), forKey: kSecAttrKeyTypeKey)
                }
            }
        }

        public var kSecAttrKeySizeInBits : Int32?  // NSNumber
        private let kSecAttrKeySizeInBitsKey = "bsiz" 
        private func kSecAttrKeySizeInBitsAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrKeySizeInBits {
                dic.setObject(NSNumber(int: v), forKey: kSecAttrKeySizeInBitsKey)
            }
        }
        
        public var kSecAttrEffectiveKeySize : Int32? // NSNumber
        private let kSecAttrEffectiveKeySizeKey = "esiz" 
        private func kSecAttrEffectiveKeySizeAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrEffectiveKeySize {
                dic.setObject(NSNumber(int: v), forKey: kSecAttrEffectiveKeySizeKey)
            }
        }
        
        public var kSecAttrCanEncrypt : Bool? // NSNumber
        private let kSecAttrCanEncryptKey = "encr" 
        private func kSecAttrCanEncryptAddToDic(dic : NSMutableDictionary) {
            if (kSecAttrCanEncrypt != nil && kSecAttrCanEncrypt!) {
                dic.setObject(NSNumber(bool: true), forKey: kSecAttrCanEncryptKey)
            }
        }

        
        public var kSecAttrCanDecrypt : Bool? // NSNumber
        private let kSecAttrCanDecryptKey = "decr" 
        private func kSecAttrCanDecryptAddToDic(dic : NSMutableDictionary) {
            if kSecAttrCanDecrypt != nil && kSecAttrCanDecrypt! {
                dic.setObject(NSNumber(bool: true), forKey: kSecAttrCanDecryptKey)
            }
        }
        
        public var kSecAttrCanDerive : Bool? // NSNumber
        private let kSecAttrCanDeriveKey = "drve" 
        private func kSecAttrCanDeriveAddToDic(dic : NSMutableDictionary) {
            if kSecAttrCanDerive != nil && kSecAttrCanDerive! {
                dic.setObject(NSNumber(bool: true), forKey: kSecAttrCanDeriveKey)
            }
        }

        
        public var kSecAttrCanSign : Bool? // NSNumber
        private let kSecAttrCanSignKey = "sign" 
        private func kSecAttrCanSignAddToDic(dic : NSMutableDictionary) {
            if (kSecAttrCanSign != nil && kSecAttrCanSign!) {
                dic.setObject(NSNumber(bool: true), forKey: kSecAttrCanSignKey)
            }
        }

        
        public var kSecAttrCanVerify : Bool? // NSNumber
        private let kSecAttrCanVerifyKey = "vrfy" 
        
        
        public var kSecAttrCanWrap : Bool? // NSNumber
        private let kSecAttrCanWrapKey = "wrap" 
        private func kSecAttrCanWrapAddToDic(dic : NSMutableDictionary) {
            if (kSecAttrCanWrap != nil  && kSecAttrCanWrap!) {
                dic.setObject(NSNumber(bool: true), forKey: kSecAttrCanWrapKey)
            }
        }

        
        public var kSecAttrCanUnwrap : Bool? // NSNumber
        private let kSecAttrCanUnwrapKey = "unwp" 
        private func kSecAttrCanUnwrapAddToDic(dic : NSMutableDictionary) {
            if (kSecAttrCanUnwrap != nil && kSecAttrCanUnwrap!) {
                dic.setObject(NSNumber(bool: true), forKey: kSecAttrCanUnwrapKey)
            }
        }

        public var kSecAttrAccessGroup : String?
        private let kSecAttrAccessGroupKey = "agrp"
         private func kSecAttrAccessGroupAddToDic(dic : NSMutableDictionary) {
            if let v = kSecAttrAccessGroup {
                dic.setObject(v, forKey: kSecAttrAccessGroupKey)
            }
        }
        
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Search Attributes
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        
        public var kSecMatchPolicy : SecPolicyRef?
        private let kSecMatchPolicyKey = "m_Policy"
         private func kSecMatchPolicyAddToDic(dic : NSMutableDictionary) {
            if let v = kSecMatchPolicy {
                dic.setObject(v, forKey: kSecMatchPolicyKey)
            }
        }
        
        public var kSecMatchItemList : NSArray?
        private let kSecMatchItemListKey = "m_ItemList"
         private func kSecMatchItemListAddToDic(dic : NSMutableDictionary) {
            if let v = kSecMatchItemList {
                dic.setObject(v, forKey: kSecMatchItemListKey)
            }
        }
        
        public var kSecMatchSearchList : NSArray?
        private let kSecMatchSearchListKey = "m_SearchList"
         private func kSecMatchSearchListAddToDic(dic : NSMutableDictionary) {
            if let v = kSecMatchSearchList {
                dic.setObject(v, forKey: kSecMatchSearchListKey)
            }
        }
        
        public var kSecMatchIssuers : [NSData]?
        private let kSecMatchIssuersKey = "m_Issuers"
        private func kSecMatchIssuersAddToDic(dic : NSMutableDictionary) {
            if let v = kSecMatchIssuers {
                dic.setObject(v, forKey: kSecMatchIssuersKey)
            }
        }
        
        public var kSecMatchEmailAddressIfPresent : String?
        private let kSecMatchEmailAddressIfPresentKey = "m_EmailAddressIfPresent"
        private func kSecMatchEmailAddressIfPresentAddToDic(dic : NSMutableDictionary) {
            if let v = kSecMatchEmailAddressIfPresent {
                dic.setObject(v, forKey: kSecMatchEmailAddressIfPresentKey)
            }
        }
        
        public var kSecMatchSubjectContains : String?
        private let kSecMatchSubjectContainsKey = "m_SubjectContains"
        private func kSecMatchSubjectContainsAddToDic(dic : NSMutableDictionary) {
            if let v = kSecMatchSubjectContains {
                dic.setObject(v, forKey: kSecMatchSubjectContainsKey)
            }
        }
        
        public var kSecMatchCaseInsensitive : Bool = false
        private let kSecMatchCaseInsensitiveKey = "m_CaseInsensitive"
        private func kSecMatchCaseInsensitiveAddToDic(dic : NSMutableDictionary) {
            if kSecMatchCaseInsensitive {
                dic.setObject(NSNumber(bool: true), forKey: kSecMatchCaseInsensitiveKey)
            }
        }

        
        public var kSecMatchTrustedOnly : Bool = false
        private let kSecMatchTrustedOnlyKey = "m_TrustedOnly"
        private func kSecMatchTrustedOnlyAddToDic(dic : NSMutableDictionary) {
            if kSecMatchTrustedOnly {
                dic.setObject(NSNumber(bool: true), forKey: kSecMatchTrustedOnlyKey)
            }
        }

        
        public var kSecMatchValidOnDate : NSDate?
        private let kSecMatchValidOnDateKey = "m_ValidOnDate"
        private func kSecMatchValidOnDateAddToDic(dic : NSMutableDictionary) {
            if let v = kSecMatchValidOnDate {
                dic.setObject(v, forKey: kSecMatchValidOnDateKey)
            }
        }
        
        
        public var kSecMatchLimit : KSecMatchLimitValue?
        private let kSecMatchLimitKey = "m_Limit"
        private let kSecMatchLimitOneKey = "m_LimitOne"
        private let kSecMatchLimitAllKey = "m_LimitAll"
        public enum KSecMatchLimitValue {
            case kSecMatchLimitOne
            case kSecMatchLimitAll
            case limit(Int)
        }
        private func kSecMatchLimitAddToDic(dic : NSMutableDictionary) {
            if let v = kSecMatchLimit {
                switch v {
                case .kSecMatchLimitOne:
                    dic.setObject(kSecMatchLimitOneKey, forKey: kSecMatchLimitKey)
                    
                case .kSecMatchLimitAll:
                    dic.setObject(kSecMatchLimitAllKey, forKey: kSecMatchLimitKey)
                    
                case let .limit(val):
                    dic.setObject(NSNumber(long: val), forKey: kSecMatchLimitKey)
   
                }
            }
        }
        
 
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Item List
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        
        
        public var kSecUseItemList : KSecUseItemListValue?
        private let kSecUseItemListKey = "u_ItemList"
        public enum KSecUseItemListValue {
            //case KeychainItems([SecKeychainItemRef])
            case Keys([SecKeyRef])
            case Certificates([SecCertificateRef])
            case Identities([SecIdentityRef])
            case PersistentItems([NSData])
        }
        private func kSecUseItemListAddToDic(dic : NSMutableDictionary) {
            if let v = kSecUseItemList {
                switch v {
                case let .Keys(val):
                    dic.setObject(val, forKey: kSecUseItemListKey)
                    
                case let .Certificates(val):
                    dic.setObject(val, forKey: kSecUseItemListKey)
                    
                case let .Identities(val):
                    dic.setObject(val, forKey: kSecUseItemListKey)
                
                case let .PersistentItems(val):
                    dic.setObject(val, forKey: kSecUseItemListKey)
                }
            }
        }
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Helper functions
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
     
        public func toNSDictionary() -> NSDictionary
        {
            let dic = NSMutableDictionary()
            
            let addFunctions = [
                kSecClassAddToDic,
                kSecReturnDataAddToDic,
                kSecReturnAttributesAddToDic,
                kSecReturnRefAddToDic,
                kSecReturnPersistentRefAddToDic,
                kSecValueDataAddToDic,
                kSecValueRefAddToDic,
                kSecValuePersistentRefAddToDic,
                kSecAttrAccessibleAddToDic,
                kSecAttrCreationDateAddToDic,
                kSecAttrModificationDateAddToDic,
                kSecAttrDescriptionAddToDic,
                kSecAttrCommentAddToDic,
                kSecAttrCreatorAddToDic,
                kSecAttrTypeAddToDic,
                kSecAttrLabelAddToDic,
                kSecAttrIsInvisibleAddToDic,
                kSecAttrIsNegativeAddToDic,
                kSecAttrAccountAddToDic,
                kSecAttrServiceAddToDic,
                kSecAttrGenericAddToDic,
                kSecAttrSecurityDomainAddToDic,
                kSecAttrServerAddToDic,
                kSecAttrProtocolAddToDic,
                kSecAttrAuthenticationTypeAddToDic,
                kSecAttrPortAddToDic,
                kSecAttrPathAddToDic,
                kSecAttrSubjectAddToDic,
                kSecAttrIssuerAddToDic,
                kSecAttrSerialNumberAddToDic,
                kSecAttrSubjectKeyIDAddToDic,
                kSecAttrPublicKeyHashAddToDic,
                kSecAttrCertificateTypeAddToDic,
                kSecAttrCertificateEncodingAddToDic,
                kSecAttrKeyClassAddToDic,
                kSecAttrApplicationLabelAddToDic,
                kSecAttrIsPermanentAddToDic,
                kSecAttrApplicationTagAddToDic,
                kSecAttrKeyTypeAddToDic,
                kSecAttrKeySizeInBitsAddToDic,
                kSecAttrEffectiveKeySizeAddToDic,
                kSecAttrCanEncryptAddToDic,
                kSecAttrCanDecryptAddToDic,
                kSecAttrCanDeriveAddToDic,
                kSecAttrCanSignAddToDic,
                kSecAttrCanWrapAddToDic,
                kSecAttrCanUnwrapAddToDic,
                kSecAttrAccessGroupAddToDic,
                kSecMatchPolicyAddToDic,
                kSecMatchItemListAddToDic,
                kSecMatchSearchListAddToDic,
                kSecMatchIssuersAddToDic,
                kSecMatchEmailAddressIfPresentAddToDic,
                kSecMatchSubjectContainsAddToDic,
                kSecMatchCaseInsensitiveAddToDic,
                kSecMatchTrustedOnlyAddToDic,
                kSecMatchValidOnDateAddToDic,
                kSecMatchLimitAddToDic,
                kSecUseItemListAddToDic]
            
            
            for f in addFunctions {
                f(dic)
            }

            return dic
        }
    }
    
    /**
    A Swift wrapper of OSStatus SecItemAdd(CFDictionaryRef attributes,CFTypeRef *result) C function.
    
    :param: query An object wrapping a CFDictionaryRef with attributes
    :returns: A pair containing the result code and an NSObject that was returned in the result parameter of SecItemAdd call.
    
    */
    
    public class func secItemAdd(#query : Query) -> (status: ResultCode, result: NSObject?)
    {
        let dic = query.toNSDictionary()
        let resultAndStatus = CXKeychainHelper.secItemAddCaller(query.toNSDictionary() as [NSObject : AnyObject])
        let status = ResultCode.fromRaw(resultAndStatus.status)
        return (status: status, result: resultAndStatus.result)
    }
    
    /**
    A Swift wrapper of OSStatus SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) C function.
    
    :param: query An object wrapping a CFDictionaryRef with query
    :returns: A pair containing the result code and an NSObject that was returned in the result parameter of SecItemCopyMatching call.
    
    */
    public class func secItemCopyMatching(#query : Query) -> (status: ResultCode, result: NSObject?)
    {
        let dic : NSDictionary = query.toNSDictionary()
        let resultAndStatus = CXKeychainHelper.secItemCopyMatchingCaller(dic as [NSObject : AnyObject])
        return (status: ResultCode.fromRaw(resultAndStatus.status), result: resultAndStatus.result)
    }
    
    /**
    A Swift wrapper of OSStatus SecItemDelete(CFDictionaryRef query) C function.
    
    :param: query An object wrapping a CFDictionaryRef with query
    :returns: A result code.
    
    */
    
    public class func secItemDelete(#query : Query) -> ResultCode
    {
        let statusRaw = SecItemDelete(query.toNSDictionary())
        let status = ResultCode.fromRaw(statusRaw)
        return status
    }

    /**
    A Swift wrapper of OSStatus SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) C function.
    
    :param: query An object wrapping a CFDictionaryRef with query
    :param: attributesToUpdate An object wrapping a CFDictionaryRef with attributesToUpdate
    :returns: A result code.
    
    */
    public class func secItemUpdate(#query : Query, attributesToUpdate : Query) -> ResultCode
    {
        let statusRaw = SecItemUpdate(query.toNSDictionary(),attributesToUpdate.toNSDictionary())
        let status = ResultCode.fromRaw(statusRaw)
        return status
    }
    

}
