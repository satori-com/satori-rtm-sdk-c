#import <Foundation/Foundation.h>
#import <SatoriSDK/rtm.h>

@interface SatoriPdu : NSObject

@property (nonatomic, readonly) enum rtm_action_t action;
@property (nonatomic, readonly) NSDictionary *_Nonnull fields;
@property (nonatomic, readonly) unsigned requestId;

- (nullable instancetype)init __attribute__((unavailable("Must use initWithAction:fields:andRequestId: instead.")));
- (nullable instancetype)initWithAction:(enum rtm_action_t)action fields:(NSDictionary *_Nonnull)fields andRequestId:(unsigned)requestId;
- (nullable instancetype)initWithLowLevelPdu:(const rtm_pdu_t *_Nonnull)pdu;


@end
