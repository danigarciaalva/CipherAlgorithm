//
//  ViewController.swift
//  CipherAlgorithm
//
//  Created by Daniel Garcia Alvarado on 1/25/17.
//  Copyright © 2017 Dragonfly Labs. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        let text = "Esto es una prueba" as NSString
        let base64 = crypt(text: text)
        print(base64)
        let back = decrypt(text: base64)
        print(back)
    }
    
    func printData(data: NSData){
        var array = [UInt8](repeating: 0, count: data.length)
        data.getBytes(&array, length: data.length)
        print(array)
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }
    
    func crypt(text: NSString) -> String{
        let secretKey = "oaguser" as NSString
        let cString = secretKey.cString(using: String.Encoding.utf8.rawValue)
        let digestOfPassword = NSData(bytes: cString, length: secretKey.length).MD5()
        let keyData = digestOfPassword.copyWithCount(count: 24)
        
        let cStringText = text.cString(using: String.Encoding.utf8.rawValue)
        let encryptData = NSData(bytes: cStringText, length: text.length)
        
        
        let buffer_size : size_t = keyData.length + kCCBlockSize3DES
        let buffer = UnsafeMutablePointer<NSData>.allocate(capacity: buffer_size)
        var num_bytes_encrypted : size_t = 0
        
        let operation: CCOperation = UInt32(kCCEncrypt)
        let algoritm:  CCAlgorithm = UInt32(kCCAlgorithm3DES)
        let options:   CCOptions   = UInt32(kCCOptionECBMode + kCCOptionPKCS7Padding)
        let keyLength        = size_t(kCCKeySize3DES)
        
        let Crypto_status: CCCryptorStatus = CCCrypt(operation, algoritm, options, keyData.bytes, keyLength, nil, encryptData.bytes, encryptData.length, buffer, buffer_size, &num_bytes_encrypted)
        
        if UInt32(Crypto_status) == UInt32(kCCSuccess){
            let result: NSData = NSData(bytes: buffer, length: num_bytes_encrypted)
            free(buffer)
            return result.base64EncodedString(options: [])
        }else{
            free(buffer)
            return ""
        }   
    }
    
    func decrypt(text: String) -> String{
        let secretKey = "oaguser" as NSString
        let cString = secretKey.cString(using: String.Encoding.utf8.rawValue)
        let digestOfPassword = NSData(bytes: cString, length: secretKey.length).MD5()
        let keyData = digestOfPassword.copyWithCount(count: 24)
        
        let base64 = NSData(base64Encoded: text, options: [])
        
        
        let buffer_size : size_t = keyData.length + kCCBlockSize3DES
        let buffer = UnsafeMutablePointer<NSData>.allocate(capacity: buffer_size)
        var num_bytes_encrypted : size_t = 0
        
        let operation: CCOperation = UInt32(kCCDecrypt)
        let algoritm:  CCAlgorithm = UInt32(kCCAlgorithm3DES)
        let options:   CCOptions   = UInt32(kCCOptionECBMode + kCCOptionPKCS7Padding)
        let keyLength        = size_t(kCCKeySize3DES)
        
        let Crypto_status: CCCryptorStatus = CCCrypt(operation, algoritm, options, keyData.bytes, keyLength, nil, base64!.bytes, base64!.length, buffer, buffer_size, &num_bytes_encrypted)
        
        if UInt32(Crypto_status) == UInt32(kCCSuccess){
            let result: NSData = NSData(bytes: buffer, length: num_bytes_encrypted)
            free(buffer)
            return String(data: result as Data, encoding: String.Encoding.utf8)!
        }else{
            free(buffer)
            return ""
        }
    }

    
}

extension NSData {
    
    func MD5() -> NSData {
        var hash: [UInt8] = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        CC_MD5(self.bytes, CC_LONG(self.length), &hash)
        return NSData(bytes: &hash, length: hash.count)
    }
    
    func copyWithCount(count: Int) -> NSData {
        var array = [UInt8](repeating: 0, count: count)
        self.getBytes(&array, length:self.length)
        return NSData(bytes: array, length: count)
    }
}

