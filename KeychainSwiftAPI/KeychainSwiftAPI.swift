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
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Return data type
        /////////////////////////////////////////////////////////////////////////////////////////////////////////

        
        public var kSecReturnData : Bool = false
        private let kSecReturnDataKey = "r_Data"
        
        public var kSecReturnAttributes : Bool = false
        private let kSecReturnAttributesKey = "r_Attributes"
        
        public var kSecReturnRef : Bool = false
        private let kSecReturnRefKey = "r_Ref"
        
        public var kSecReturnPersistentRef : Bool = false
        private let kSecReturnPersistentRefKey = "r_PersistentRef"
        
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Value
        /////////////////////////////////////////////////////////////////////////////////////////////////////////

        
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
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Attributes
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
       
        public var kSecAttrAccessible : KSecAttrAccessibleValue?
        private let kSecAttrAccessibleKey = "pdmn"
        public enum KSecAttrAccessibleValue : String {
            case kSecAttrAccessibleWhenUnlocked = "ak"
            case kSecAttrAccessibleAfterFirstUnlock = "ck"
            case kSecAttrAccessibleAlways = "dk"
            case kSecAttrAccessibleWhenUnlockedThisDeviceOnly = "aku"
            case kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = "cku"
            case kSecAttrAccessibleAlwaysThisDeviceOnly = "dku"
        }
        

        
        public var kSecAttrCreationDate : NSDate?
        private let kSecAttrCreationDateKey = "cdat"
        
        
        public var kSecAttrModificationDate : NSDate?
        private let kSecAttrModificationDateKey = "mdat"
        
        
        public var kSecAttrDescription : String?
        private let kSecAttrDescriptionKey = "desc"
        
        
        public var kSecAttrComment : String?
        private let kSecAttrCommentKey = "icmt"
        
        
        public var kSecAttrCreator : UInt? // NSNumber with unsigned integer
        private let kSecAttrCreatorKey = "crtr"
        
        
        public var kSecAttrType : UInt? // NSNumber with unsigned integer
        private let kSecAttrTypeKey = "type"
        
        
        public var kSecAttrLabel : String?
        private let kSecAttrLabelKey = "labl"
        
        
        public var kSecAttrIsInvisible : Bool = false // NSNumber with bool
        private let kSecAttrIsInvisibleKey = "invi"
        
        
        public var kSecAttrIsNegative : Bool = false // NSNumber with bool
        private let kSecAttrIsNegativeKey = "nega"
        
        
        public var kSecAttrAccount : String?
        private let kSecAttrAccountKey = "acct"
        
        
        public var kSecAttrService : String?
        private let kSecAttrServiceKey = "svce"
        
        
        public var kSecAttrGeneric : NSData?
        private let kSecAttrGenericKey = "gena"
        
        
        public var kSecAttrSecurityDomain : String?
        private let kSecAttrSecurityDomainKey = "sdmn"
        
        
        public var kSecAttrServer : String?
        private let kSecAttrServerKey = "srvr"
        
        
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

        
        public var kSecAttrPort : UInt? // NSNumber unsigned
        private let kSecAttrPortKey = "port"
        
        
        public var kSecAttrPath : String?
        private let kSecAttrPathKey = "path"
        
        
        public var kSecAttrSubject : NSData?
        private let kSecAttrSubjectKey = "subj"
        
        
        public var kSecAttrIssuer : NSData?
        private let kSecAttrIssuerKey = "issr"
        
        
        public var kSecAttrSerialNumber : NSData?
        private let kSecAttrSerialNumberKey = "slnr"
        
        
        public var kSecAttrSubjectKeyID : NSData?
        private let kSecAttrSubjectKeyIDKey = "skid"
        
        
        public var kSecAttrPublicKeyHash : NSData?
        private let kSecAttrPublicKeyHashKey = "pkhh"
        
        
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
        
        public var kSecAttrKeyClass : KSecAttrKeyClassValue?
        private let kSecAttrKeyClassKey = "kcls"
        public enum KSecAttrKeyClassValue : String {
            case kSecAttrKeyClassPublic = "0"
            case kSecAttrKeyClassPrivate = "1"
            case kSecAttrKeyClassSymmetric = "2"
        }
        
        public var kSecAttrApplicationLabel : String?
        private let kSecAttrApplicationLabelKey = "klbl"
        
        
        public var kSecAttrIsPermanent : Bool? // NSNumber bool
        private let kSecAttrIsPermanentKey = "perm"
        
        
        public var kSecAttrApplicationTag : NSData?
        private let kSecAttrApplicationTagKey = "atag"
        
        
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
        
        public var kSecAttrKeySizeInBits : Int?  // NSNumber
        private let kSecAttrKeySizeInBitsKey = "bsiz" 
        
        
        public var kSecAttrEffectiveKeySize : Int? // NSNumber
        private let kSecAttrEffectiveKeySizeKey = "esiz" 
        
        
        public var kSecAttrCanEncrypt : Bool? // NSNumber
        private let kSecAttrCanEncryptKey = "encr" 
        
        
        public var kSecAttrCanDecrypt : Bool? // NSNumber
        private let kSecAttrCanDecryptKey = "decr" 
        
        
        public var kSecAttrCanDerive : Bool? // NSNumber
        private let kSecAttrCanDeriveKey = "drve" 
        
        
        public var kSecAttrCanSign : Bool? // NSNumber
        private let kSecAttrCanSignKey = "sign" 
        
        
        public var kSecAttrCanVerify : Bool? // NSNumber
        private let kSecAttrCanVerifyKey = "vrfy" 
        
        
        public var kSecAttrCanWrap : Bool? // NSNumber
        private let kSecAttrCanWrapKey = "wrap" 
        
        
        public var kSecAttrCanUnwrap : Bool? // NSNumber
        private let kSecAttrCanUnwrapKey = "unwp" 
        
        public var kSecAttrAccessGroup : String?
        private let kSecAttrAccessGroupKey = "agrp"
        
        /////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Helper functions
        /////////////////////////////////////////////////////////////////////////////////////////////////////////

        
        
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