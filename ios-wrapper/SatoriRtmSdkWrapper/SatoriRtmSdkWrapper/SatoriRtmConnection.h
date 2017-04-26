#import <Foundation/Foundation.h>
#import "SatoriPdu.h"
#import "rtm.h"

typedef void (^PduHandler)(SatoriPdu* _Nonnull pdu);
typedef void (^MessageHandler)(NSString* _Nullable subscriptionId, id _Nullable message);

@interface SatoriRtmConnection : NSObject

@property (nonnull, class, nonatomic, strong, readonly) PduHandler defaultPduHandler;
@property (nonatomic, assign) BOOL enableVerboseLogging;

#pragma mark Initializer
- (nullable instancetype)init __attribute__((unavailable("Must use initWithUrl:andAppkey: instead.")));
- (nullable instancetype)initWithUrl:(nonnull NSString*)url andAppkey:(nonnull NSString*)appKey;

#pragma mark Connection
- (rtm_status)connect;
- (rtm_status)connectWithPduHandler:(nonnull PduHandler)pduHandler;
- (void)disconnect;
- (rtm_status)handshakeWithRole:(nonnull NSString*)role andRequestId:(nullable unsigned *)requestId;
- (rtm_status)authenticate:(nonnull NSString *)roleSecret nonce:(nonnull NSString*)nonce andRequestId:(nullable unsigned *)requestId;
- (rtm_status)wait;
- (rtm_status)waitWithTimeout:(int)timeoutInSeconds;
- (rtm_status)poll;
- (int)getFileDescriptor;

#pragma mark PubSub
- (rtm_status)publishJson:(nonnull NSString*)json toChannel:(nonnull NSString*)channel andRequestId:(nullable unsigned *)requestId;
- (rtm_status)publishString:(nonnull NSString*)string toChannel:(nonnull NSString*)channel andRequestId:(nullable unsigned *)requestId;
- (rtm_status)subscribe:(nonnull NSString*)channel andRequestId:(nullable unsigned *)requestId;
- (rtm_status)subscribeWithBody:(nonnull NSString*)body andRequestId:(nullable unsigned *)requestId;
- (rtm_status)unsubscribe:(nonnull NSString*)channel andRequestId:(nullable unsigned *)requestId;

#pragma mark Read/Write
- (rtm_status)read:(nonnull NSString*)channel andRequestId:(nullable unsigned *)requestId;
- (rtm_status)readWithBody:(nonnull NSString*)body andRequestId:(nullable unsigned *)requestId;
- (rtm_status)writeString:(nonnull NSString*)string channel:(nonnull NSString*)channel andRequestId:(nullable unsigned *)requestId;
- (rtm_status)writeJson:(nonnull NSString*)json channel:(nonnull NSString*)channel andRequestId:(nullable unsigned *)requestId;
- (rtm_status)sendPdu:(nonnull NSString*)json;

#pragma mark Parsing
+ (nullable SatoriPdu*)parsePdu:(nonnull NSString*)json;

#pragma mark Delete
- (rtm_status)deleteFromChannel:(nonnull NSString*)channel andRequestId:(nullable unsigned *)requestId;

#pragma mark Search
- (rtm_status)search:(nonnull NSString*)prefix andRequestId:(nullable unsigned *)requestId;

@end
