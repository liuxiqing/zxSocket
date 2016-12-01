//
//  ViewController.h
//  zxSocket
//
//  Created by 张 玺 on 12-3-24.
//  Copyright (c) 2012年 张玺. All rights reserved.
//

#import <UIKit/UIKit.h>
#import "GCDAsyncSocket.h"


@interface ViewController : UIViewController<GCDAsyncSocketDelegate,UITextFieldDelegate>
{
    GCDAsyncSocket *socket;
}

@property(strong)  GCDAsyncSocket *socket;
@property (nonatomic, strong) NSString *sessionID;
@property (nonatomic, strong) NSData *revData;
@property (nonatomic, strong) NSData *saveData;
@property (nonatomic, assign) uint32_t byteCount;
@property (nonatomic, assign) NSUInteger leftByteCount;
@property (nonatomic, assign) BOOL isNewData;
@property (nonatomic, strong) NSString *tlsKey;

@property (nonatomic, strong) NSString *firstRandomKey;
@property (nonatomic, strong) NSString *secondRandomKey;

@property (strong, nonatomic) IBOutlet UITextField *host;
@property (strong, nonatomic) IBOutlet UITextField *message;
@property (strong, nonatomic) IBOutlet UITextField *port;
@property (strong, nonatomic) IBOutlet UITextView *status;

- (IBAction)connect:(id)sender;
- (IBAction)send:(id)sender;

@end

