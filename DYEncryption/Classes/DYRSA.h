//
//  DYRSA.h
//  DYEncryption
//
//  Created by zdy on 2017/3/23.
//  Copyright © 2017年 lianlianpay. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface DYRSA : NSObject
// 使用公钥文件.der 加密，返回base64 string
+ (NSString *)encryptString:(NSString *)str publicKeyWithContentsOfFile:(NSString *)path;
// 使用私钥文件.p12 加密，返回base64 string
+ (NSString *)encryptString:(NSString *)str privateKeyWithContentsOfFile:(NSString *)path password:(NSString*)password;
// 使用公钥字符串加密，返回base64 string，公钥字符串为pem 里面内容
+ (NSString *)encryptString:(NSString *)str publicKey:(NSString *)pubKey;

// 使用公钥文件.der 解密，传入base64 string
+ (NSString *)decryptString:(NSString *)str publicKeyWithContentsOfFile:(NSString *)path;
// 使用私钥文件.p12 解密，传入base64 string
+ (NSString *)decryptString:(NSString *)str privateKeyWithContentsOfFile:(NSString *)path password:(NSString*)password;
// 使用公钥字符串解密，传入base64 string
+ (NSString *)decryptString:(NSString *)str publicKey:(NSString *)pubKey;

// str 为做过hash签名的字符串
+ (NSString *)signStrig:(NSString *)str privateKeyWithContentsOfFile:(NSString *)path password:(NSString*)password;
@end
