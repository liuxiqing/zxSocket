//
//  ViewController.m
//  zxSocket
//
//  Created by 张 玺 on 12-3-24.
//  Copyright (c) 2012年 张玺. All rights reserved.
//

#import "ViewController.h"
#import "NSData+Encryption.h"
#import <CommonCrypto/CommonDigest.h>
#import "RSA.h"

#define MethodKey @"method"
#define ParasKey @"paras"
#define TLSKey @"TLSKey"
#define RandomKey @"RandomKey"
#define MD5Key @"MD5Key"

@implementation ViewController
@synthesize socket;
@synthesize host;
@synthesize message;
@synthesize port;
@synthesize status;


- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Release any cached data, images, etc that aren't in use.
}

#pragma mark - View lifecycle
-(void)addText:(NSString *)str {
    status.text = [status.text stringByAppendingFormat:@"%@\n",str];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    host.text = @"112.115.111.191";
    port.text = @"54321";
    
	// Do any additional setup after loading the view, typically from a nib.
}

-(BOOL)textFieldShouldReturn:(UITextField *)textField {
    [textField resignFirstResponder];
    return YES;
}

- (void)viewDidUnload {
    [self setHost:nil];
    [self setMessage:nil];
    [self setStatus:nil];
    [self setPort:nil];
    [super viewDidUnload];
    
    // Release any retained subviews of the main view.
    // e.g. self.myOutlet = nil;
}

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
}

- (void)viewDidAppear:(BOOL)animated
{
    [super viewDidAppear:animated];
}

- (void)viewWillDisappear:(BOOL)animated
{
	[super viewWillDisappear:animated];
}

- (void)viewDidDisappear:(BOOL)animated
{
	[super viewDidDisappear:animated];
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    // Return YES for supported orientations
    return (interfaceOrientation != UIInterfaceOrientationPortraitUpsideDown);
}

- (IBAction)connect:(id)sender {
    [self clearAllState];
    socket = [[GCDAsyncSocket alloc]initWithDelegate:self delegateQueue:dispatch_get_main_queue()]; 
    //socket.delegate = self;
    NSError *err = nil; 
    if(![socket connectToHost:host.text onPort:[port.text intValue] error:&err]) 
    {
       
        [self addText:err.description];
    }else
    {
        NSLog(@"ok");
        [self firstHandleShake];
        [self addText:@"打开端口"];
    }
}
-(void)socket:(GCDAsyncSocket *)sock didConnectToHost:(NSString *)hosta port:(uint16_t)port
{
    [self addText:[NSString stringWithFormat:@"连接到:%@",hosta]];
    [socket readDataWithTimeout:-1 tag:0];
}


- (void)socketDidDisconnect:(GCDAsyncSocket *)sock withError:(NSError *)err
{
}
- (IBAction)send:(id)sender {
//    NSData *data = UIImagePNGRepresentation([UIImage imageNamed:@"2345"]);//[data base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed]
    if (self.tlsKey) {
        //原始数据
        NSString *originalString = @"超能天然皂粉";
        
        NSLog(@"加密前:%@", originalString);
        
        [socket writeData:[self callWebservice:@"hello" paras:@[@{@"test":@"123"}, @{@"message":originalString}]] withTimeout:-1 tag:0];
        
        [self addText:[NSString stringWithFormat:@"我:%@",message.text]];
        [message resignFirstResponder];
    }   else    {
        //链接失败
        NSLog(@"链接失败，请重新连接服务器！");
    }
    
//    [socket readDataWithTimeout:-1 tag:0];
    
}
-(void)socket:(GCDAsyncSocket *)sock didReadData:(NSData *)data withTag:(long)tag
{
    if (self.isNewData) {
        self.isNewData = false;
        unsigned char fourByteArray[4];
        if (data.length > 4) {
            [data getBytes:&fourByteArray length:4];
            [self postLogPrint:[NSString stringWithFormat:@"---%@--- 4 bytes: %x %x %x %x", self.socket.connectedHost,fourByteArray[0],fourByteArray[1],fourByteArray[2],fourByteArray[3]]];
            self.byteCount = ((fourByteArray[3]<<24)&0xff000000)+((fourByteArray[2]<<16)&0xff0000)+((fourByteArray[1]<<8)&0xff00)+(fourByteArray[0] & 0xff);
            self.leftByteCount = self.byteCount;
            [self postLogPrint:[NSString stringWithFormat:@"bytes count: %u", self.byteCount]];
            NSUInteger length = data.length - 4;
            unsigned char dataArray[length];
            [data getBytes:&dataArray range:NSMakeRange(4, length)];
            self.revData = [NSData dataWithBytes:dataArray length:length];
            self.leftByteCount = self.leftByteCount - length;
            if (self.leftByteCount == 0) {
                self.isNewData = true;
                [self postLogPrint:[NSString stringWithFormat:@"---%@--- 数据接收完毕！总接受到：%u bytes", self.socket.connectedHost, self.byteCount]];
                [self resovleData:self.revData];
                [self clearRevState];
            }
        }   else    {
            self.isNewData = true;
            [self postLogPrint:[NSString stringWithFormat:@"---%@--- 数据头部不正确！头部应为：4 bytes, 接受到：%ld bytes", self.socket.connectedHost, data.length]];
            [self clearAllState];
        }
    }   else    {
        NSUInteger length = data.length;
        if (self.leftByteCount < length) {
            self.isNewData = true;
            [self postLogPrint:[NSString stringWithFormat:@"---%@--- 数据长度不正确！剩余：%ld bytes, 接受到：%ld bytes", self.socket.connectedHost, self.leftByteCount, length]];
            [self clearAllState];
        }   else    {
            unsigned char dataArray[length];
            [data getBytes:&dataArray length:length];
            NSMutableData *mutableData = [[NSMutableData alloc] initWithData:self.revData];
            [mutableData appendData:[NSData dataWithBytes:&dataArray length:length]];
            self.revData = [mutableData copy];
            self.leftByteCount = self.leftByteCount - length;
            [self postLogPrint:[NSString stringWithFormat:@"---%@--- 接受到数据：%ld bytes", self.socket.connectedHost, self.byteCount - self.leftByteCount]];
            if (self.leftByteCount == 0) {
                self.isNewData = true;
                [self postLogPrint:[NSString stringWithFormat:@"---%@--- 数据接收完毕！总接受到：%u bytes", self.socket.connectedHost, self.byteCount]];
                [self resovleData:self.revData];
                [self clearRevState];
            }
        }
    }
    //    [s writeData:[reply dataUsingEncoding:NSUTF8StringEncoding] withTimeout:-1 tag:0];
    [self.socket readDataWithTimeout:-1 tag:0];
}

#pragma mark - socket
//调用webservice
- (NSData *)callWebservice:(NSString *)method paras:(NSArray<NSDictionary *> *)paras {
    NSDictionary *package = @{MethodKey:method,ParasKey:paras};
    NSData *jsonData = [[self convertToJSONData:package] AES256ParmEncryptWithKey:self.tlsKey];
    uint32_t lenght = (uint32_t)jsonData.length;
    NSData *headData = [NSData dataWithBytes:&lenght length:sizeof(uint32_t)];
    NSMutableData *fullData = [[NSMutableData alloc] initWithData:headData];
    [fullData appendData:jsonData];
    return [fullData copy];
}

//将字典对象转换成json对象数据
- (NSData *)convertToJSONData:(id)infoDict
{
    NSError *error;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:infoDict
                                                       options:NSJSONWritingPrettyPrinted // Pass 0 if you don't care about the readability of the generated string
                                                         error:&error];
    if (! jsonData) {
        NSLog(@"Got an error: %@", error);
        return nil;
    }   else   {
        return jsonData;
    }
}

#pragma mark - socket
//清除所有状态和数据
- (void)clearAllState {
    self.firstRandomKey = 0;
    self.secondRandomKey = 0;
    self.tlsKey = nil;
    self.byteCount = 0;
    self.leftByteCount = 0;
    self.isNewData = true;
    self.revData = nil;
}

//清除存储的数据
- (void)clearRevState {
    self.byteCount = 0;
    self.leftByteCount = 0;
    self.isNewData = true;
    self.revData = nil;
}

//解析接受到的数据
- (void)resovleData:(NSData *)data {
    if (self.tlsKey)   {
        NSError *error;
        NSDictionary *json = [NSJSONSerialization JSONObjectWithData:[data AES256ParmDecryptWithKey:self.tlsKey] options:NSJSONReadingMutableLeaves error:&error];
        if (error) {
            [self postLogPrint:[NSString stringWithFormat:@"---%@--- %@", self.socket.connectedHost, error]];
            [self postLogPrint:[NSString stringWithFormat:@"---%@--- 解析失败！非json对象！", self.socket.connectedHost]];
        }   else    {
            NSString *method = json[MethodKey];
            NSArray *paras = json[ParasKey];
            
            NSMutableDictionary *mutableDic = [[NSMutableDictionary alloc] init];
            for (NSDictionary *dic in paras) {
                NSString *key = [[dic allKeys] lastObject];
                NSString *value = dic[key];
                [mutableDic setObject:value forKey:key];
            }
            [self postLogPrint:[NSString stringWithFormat:@"---%@--- 方法名：%@，参数：%@", self.socket.connectedHost, method, paras]];
        }
    }   else if (self.secondRandomKey == 0) {
        [self secondHandleShake:data];
    }   else    {
        [self thirdHandleShake:data];
    }
}

//打印log和显示文件
- (void)postLogPrint:(NSString *)log {
    NSLog(@"%@", log);
    [self addText:[NSString stringWithFormat:@"%@", log]];
}

#pragma mark - rsa加密通信

- (NSData *)decryptRSAData:(NSData *)encodeData {
    NSString *public_key_pem = [self loadPEMResource:@"public_key"];
    RSA *rsa = [[RSA alloc] init];
    NSString *public_key = [rsa loadX509PEMPublicKey:public_key_pem];
    NSData *decodeData = [RSA decryptData:encodeData publicKey:public_key];
    return decodeData;
}

- (NSData *)encodeRSAData:(NSData *)data {
    NSString *public_key_pem = [self loadPEMResource:@"public_key"];
    RSA *rsa = [[RSA alloc] init];
    NSString *public_key = [rsa loadX509PEMPublicKey:public_key_pem];
    NSData *encodeData = [RSA encryptData:data publicKey:public_key];
    uint32_t lenght = (uint32_t)encodeData.length;
    NSData *headData = [NSData dataWithBytes:&lenght length:sizeof(uint32_t)];
    NSMutableData *fullData = [[NSMutableData alloc] initWithData:headData];
    [fullData appendData:encodeData];
    return [fullData copy];
}

//载入公钥pem
- (NSString *)loadPEMResource:(NSString *)name {
    NSBundle *bundle = [NSBundle mainBundle];
    NSURL *url = [bundle URLForResource:name withExtension:@"pem"];
    NSAssert(url != nil, @"file not found");
    NSString *pem = [NSString stringWithContentsOfURL:url encoding:NSUTF8StringEncoding error:nil];
    return pem;
}

- (void)rsaEncryptTest {
    //原始数据
    NSString *originalString = @"这是一段将要使用'.der'文件加密的字符串!";
    
    //使用.der和.p12中的公钥私钥加密解密
    NSString *public_key_pem = [self loadPEMResource:@"public_key"];
    
    RSA *rsa = [[RSA alloc] init];
    NSString *public_key = [rsa loadX509PEMPublicKey:public_key_pem];
    
    NSData *encryptStr = [RSA encryptData:[originalString dataUsingEncoding:NSUTF8StringEncoding] publicKey:public_key];
    NSLog(@"加密前:%@", originalString);
    NSLog(@"加密后:%@", encryptStr);
}

#pragma mark - 第一次握手
- (void)firstHandleShake {
    uint32_t randomNumer = (uint32_t)fabsf((float)arc4random());
    self.firstRandomKey = [NSString stringWithFormat:@"%u", randomNumer];
    NSString *str = self.firstRandomKey;
    NSDictionary *dic = @{RandomKey:str};
    NSError *error;
    NSData *data = [NSJSONSerialization dataWithJSONObject:dic options:NSJSONWritingPrettyPrinted error:&error];
    if (!error) {
        NSData *encodeData = [self encodeRSAData:data];
        [socket writeData:encodeData withTimeout:-1 tag:0];
    }   else    {
        NSLog(@"%@", error);
        [self clearAllState];
    }
}

#pragma mark - 第二次握手
- (void)secondHandleShake:(NSData *)encodeData {
    NSData *decodeData = [self decryptRSAData:encodeData];
    NSError *error;
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:decodeData options:NSJSONReadingMutableLeaves error:&error];
    if (!error) {
        NSString *md5String = dic[MD5Key];
        NSString *randomString = dic[RandomKey];
        if ([[self encryptString:self.firstRandomKey] isEqualToString:md5String]) {
            self.secondRandomKey = randomString;
            NSString *str = [NSString stringWithFormat:@"%@%@", self.firstRandomKey, self.secondRandomKey];
            NSDictionary *dicx = @{MD5Key:[self encryptString:str]};
            NSData *data = [NSJSONSerialization dataWithJSONObject:dicx options:NSJSONWritingPrettyPrinted error:&error];
            if (!error) {
                NSData *encodeData = [self encodeRSAData:data];
                [socket writeData:encodeData withTimeout:-1 tag:0];
            }   else    {
                NSLog(@"%@", error);
                [self clearAllState];
            }
        }   else    {
            NSLog(@"---第二次握手---服务器验证密钥失败---");
            [self clearAllState];
        }
    }   else    {
        NSLog(@"%@", error);
        [self clearAllState];
    }
    
}

#pragma mark - 第三次握手
- (void)thirdHandleShake:(NSData *)encodeData {
    NSData *decodeData = [self decryptRSAData:encodeData];
    NSError *error;
    NSDictionary *dic = [NSJSONSerialization JSONObjectWithData:decodeData options:NSJSONReadingMutableLeaves error:&error];
    if (!error) {
        NSString *md5String = dic[MD5Key];
        NSString *str = [NSString stringWithFormat:@"%@%@", self.firstRandomKey, self.secondRandomKey];
        if ([md5String isEqualToString:[self encryptString:[self encryptString:str]]]) {
            self.tlsKey = str;
        }   else    {
            NSLog(@"---第三次握手---服务器验证密钥失败---");
            [self clearAllState];
        }
    }   else    {
        NSLog(@"%@", error);
        [self clearAllState];
    }
}

#pragma mark - 加密字符串

- (NSString *)encryptString:(NSString *)str {
    return [self sha1:[self md5:str]];
}

- (NSString *)md5:(NSString *)input {
    const char *cStr = [input UTF8String];
    unsigned char digest[CC_MD5_DIGEST_LENGTH];
    CC_MD5( cStr, (CC_LONG)strlen(cStr), digest ); // This is the md5 call
    
    NSMutableString *output = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_MD5_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    
    NSLog(@"---MD5--- %@", output);
    return  output;
}

- (NSString*)sha1:(NSString *)input {
    const char *cstr = [input cStringUsingEncoding:NSUTF8StringEncoding];
    
    NSData *data = [NSData dataWithBytes:cstr length:input.length];
    //使用对应的CC_SHA1,CC_SHA256,CC_SHA384,CC_SHA512的长度分别是20,32,48,64
    uint8_t digest[CC_SHA1_DIGEST_LENGTH];
    //使用对应的CC_SHA256,CC_SHA384,CC_SHA512
    CC_SHA1(data.bytes, (unsigned int)data.length, digest);
    
    NSMutableString* output = [NSMutableString stringWithCapacity:CC_SHA1_DIGEST_LENGTH * 2];
    
    for(int i = 0; i < CC_SHA1_DIGEST_LENGTH; i++)
        [output appendFormat:@"%02x", digest[i]];
    
    NSLog(@"---sha1--- %@", output);
    
    return output;
}

@end


