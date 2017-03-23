//
//  DYRSA.m
//  DYEncryption
//
//  Created by zdy on 2017/3/23.
//  Copyright © 2017年 lianlianpay. All rights reserved.
//

#import "DYRSA.h"

@implementation DYRSA

+ (NSString *)base64StringWithData:(NSData *)data {
    NSData *result = [data base64EncodedDataWithOptions:0];
    NSString *ret = [[NSString alloc] initWithData:result encoding:NSUTF8StringEncoding];
    return ret;
}

+ (NSData *)dataWithBase64String:(NSString *)str {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return data;
}

+ (NSData *)stripPublicKeyHeader:(NSData *)d_key{
    // Skip ASN.1 public key header
    if (d_key == nil) return(nil);
    
    unsigned long len = [d_key length];
    if (!len) return(nil);
    
    unsigned char *c_key = (unsigned char *)[d_key bytes];
    unsigned int  idx	 = 0;
    
    if (c_key[idx++] != 0x30) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    // PKCS #1 rsaEncryption szOID_RSA_RSA
    static unsigned char seqiod[] =
    { 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00 };
    if (memcmp(&c_key[idx], seqiod, 15)) return(nil);
    
    idx += 15;
    
    if (c_key[idx++] != 0x03) return(nil);
    
    if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
    else idx++;
    
    if (c_key[idx++] != '\0') return(nil);
    
    // Now make a new NSData from this buffer
    return([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}


+ (SecKeyRef)getPublicKey:(NSString *)key{
    NSRange spos = [key rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
    NSRange epos = [key rangeOfString:@"-----END PUBLIC KEY-----"];
    if(spos.location != NSNotFound && epos.location != NSNotFound){
        NSUInteger s = spos.location + spos.length;
        NSUInteger e = epos.location;
        NSRange range = NSMakeRange(s, e-s);
        key = [key substringWithRange:range];
    }
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
    
    // This will be base64 encoded, decode it.
    NSData *data = [self dataWithBase64String:key];
    data = [self stripPublicKeyHeader:data];
    if(!data){
        return nil;
    }
    
    //a tag to read/write keychain storage
    NSString *tag = @"RSAUtil_PubKey";
    NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    
    // Delete any old lingering key with the same tag
    NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);
    
    // Add persistent version of the key to system keychain
    [publicKey setObject:data forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)
     kSecAttrKeyClass];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
     kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return nil;
    }
    
    [publicKey removeObjectForKey:(__bridge id)kSecValueData];
    [publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Now fetch the SecKeyRef version of the key
    SecKeyRef keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keyRef);
    if(status != noErr){
        return nil;
    }
    return keyRef;
}

+ (SecKeyRef)getPublicKeyRefWithContentsOfFile:(NSString *)filePath {
    NSData *certData = [NSData dataWithContentsOfFile:filePath];
    if (!certData) {
        return nil;
    }
    
    SecCertificateRef cert = SecCertificateCreateWithData(NULL, (CFDataRef)certData);
    SecKeyRef key = NULL;
    SecTrustRef trust = NULL;
    SecPolicyRef policy = NULL;
    
    if (cert != NULL) {
        policy = SecPolicyCreateBasicX509();
        if (policy) {
            if (SecTrustCreateWithCertificates((CFTypeRef)cert, policy, &trust) == noErr) {
                SecTrustResultType result;
                if (SecTrustEvaluate(trust, &result) == noErr) {
                    key = SecTrustCopyPublicKey(trust);
                }
            }
        }
    }
    
    if (policy) CFRelease(policy);
    if (trust) CFRelease(trust);
    if (cert) CFRelease(cert);
    
    return key;
}

+ (SecKeyRef)getPrivateKeyRefWithContentsOfFile:(NSString *)filePath password:(NSString*)password{
    
    NSData *p12Data = [NSData dataWithContentsOfFile:filePath];
    if (!p12Data) {
        return nil;
    }
    
    SecKeyRef privateKeyRef = NULL;
    NSMutableDictionary * options = [[NSMutableDictionary alloc] init];
    [options setObject:password forKey:(__bridge id)kSecImportExportPassphrase];
    
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    OSStatus securityError = SecPKCS12Import((__bridge CFDataRef) p12Data, (__bridge CFDictionaryRef)options, &items);
    
    if (securityError == noErr && CFArrayGetCount(items) > 0) {
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identityApp = (SecIdentityRef)CFDictionaryGetValue(identityDict, kSecImportItemIdentity);
        securityError = SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
        
        if (securityError != noErr) {
            privateKeyRef = NULL;
        }
    }
    CFRelease(items);
    
    return privateKeyRef;
}

#pragma mark - Encrypt

+ (NSString *)encryptString:(NSString *)str publicKeyWithContentsOfFile:(NSString *)path {
    if (!str.length || !path.length) {
        return nil;
    }
    
    SecKeyRef keyRef = [self getPublicKeyRefWithContentsOfFile:path];
    if (!keyRef) {
        return nil;
    }
    
    NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *result = [self encryptData:data withKeyRef:keyRef];
    
    return [self base64StringWithData:result];
}

+ (NSString *)encryptString:(NSString *)str privateKeyWithContentsOfFile:(NSString *)path password:(NSString*)password {
    if (!str.length || !path.length) {
        return nil;
    }
    
    SecKeyRef keyRef = [self getPrivateKeyRefWithContentsOfFile:path password:password];
    if (!keyRef) {
        return nil;
    }
    
    NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *result = [self encryptData:data withKeyRef:keyRef];
    
    return [self base64StringWithData:result];
}

+ (NSString *)encryptString:(NSString *)str publicKey:(NSString *)pubKey {
    if(!str.length || !pubKey.length){
        return nil;
    }
    
    SecKeyRef keyRef = [self getPublicKey:pubKey];
    if(!keyRef){
        return nil;
    }
    
    NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *result = [self encryptData:data withKeyRef:keyRef];
    NSString *ret = [self base64StringWithData:result];
    
    return ret;
}

+ (NSData *)encryptData:(NSData *)data withKeyRef:(SecKeyRef)keyRef{
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    void *outbuf = malloc(block_size);
    size_t src_block_size = block_size - 11;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for(int idx=0; idx<srclen; idx+=src_block_size){
        //NSLog(@"%d/%d block_size: %d", idx, (int)srclen, (int)block_size);
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyEncrypt(keyRef,
                               kSecPaddingPKCS1,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen
                               );
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", status);
            ret = nil;
            break;
        }else{
            [ret appendBytes:outbuf length:outlen];
        }
    }
    
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}

#pragma mark - Decrypt


+ (NSString *)decryptString:(NSString *)str privateKeyWithContentsOfFile:(NSString *)path password:(NSString*)password {
    if(!str.length || !path.length){
        return nil;
    }
    
    SecKeyRef keyRef = [self getPrivateKeyRefWithContentsOfFile:path password:password];
    if(!keyRef){
        return nil;
    }
    
    NSData *data = [self dataWithBase64String:str];
    data = [self decryptData:data withKeyRef:keyRef];
    
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}

+ (NSString *)decryptString:(NSString *)str publicKeyWithContentsOfFile:(NSString *)path {
    if(!str.length || !path.length){
        return nil;
    }
    
    SecKeyRef keyRef = [self getPublicKeyRefWithContentsOfFile:path];
    if(!keyRef){
        return nil;
    }
    
    NSData *data = [self dataWithBase64String:str];
    data = [self decryptData:data withKeyRef:keyRef];
    
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}

+ (NSString *)decryptString:(NSString *)str publicKey:(NSString *)pubKey{
    if(!str.length || !pubKey.length){
        return nil;
    }
    
    SecKeyRef keyRef = [self getPublicKey:pubKey];
    if(!keyRef){
        return nil;
    }
    
    NSData *data = [self dataWithBase64String:str];
    data = [self decryptData:data withKeyRef:keyRef];
    
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}

+ (NSData *)decryptData:(NSData *)data withKeyRef:(SecKeyRef) keyRef{
    const uint8_t *srcbuf = (const uint8_t *)[data bytes];
    size_t srclen = (size_t)data.length;
    
    size_t block_size = SecKeyGetBlockSize(keyRef) * sizeof(uint8_t);
    UInt8 *outbuf = malloc(block_size);
    size_t src_block_size = block_size;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for(int idx=0; idx<srclen; idx+=src_block_size){
        //NSLog(@"%d/%d block_size: %d", idx, (int)srclen, (int)block_size);
        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyDecrypt(keyRef,
                               kSecPaddingNone,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen
                               );
        if (status != 0) {
#ifdef DEBUG
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)status);
#endif
            ret = nil;
            break;
        }else{
            //the actual decrypted data is in the middle, locate it!
            int idxFirstZero = -1;
            int idxNextZero = (int)outlen;
            for ( int i = 0; i < outlen; i++ ) {
                if ( outbuf[i] == 0 ) {
                    if ( idxFirstZero < 0 ) {
                        idxFirstZero = i;
                    } else {
                        idxNextZero = i;
                        break;
                    }
                }
            }
            
            [ret appendBytes:&outbuf[idxFirstZero+1] length:idxNextZero-idxFirstZero-1];
        }
    }
    
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}

#pragma mark - Sign
+ (NSString *)signStrig:(NSString *)str privateKeyWithContentsOfFile:(NSString *)path password:(NSString*)password {
    if(!str.length || !path.length){
        return nil;
    }
    
    SecKeyRef keyRef = [self getPrivateKeyRefWithContentsOfFile:path password:password];
    
    if(!keyRef){
        return nil;
    }
    
    NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *result = [self signData:data withKeyRef:keyRef];
    NSString *ret = [self base64StringWithData:result];
    
    return ret;
}

+ (NSData *)signData:(NSData *)data withKeyRef:(SecKeyRef)keyRef {
    OSStatus ret;
    NSData *retData = nil;
    size_t siglen = SecKeyGetBlockSize(keyRef);
    uint8_t *sig = malloc(siglen);
    
    
    ret = SecKeyRawSign(keyRef, kSecPaddingPKCS1SHA1, data.bytes, data.length, sig, &siglen);
    if (ret==errSecSuccess) {
        retData = [NSData dataWithBytes:sig length:siglen];
    }
    
    free(sig);
    sig = NULL;
    
    return retData;
}
@end
