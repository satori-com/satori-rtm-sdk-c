#import <Foundation/Foundation.h>
#import <SatoriRtmSdkWrapper/rtm.h>

@interface SatoriPdu : NSObject

@property (nonatomic, readonly) enum rtm_action_t action;
@property (nonatomic, readonly) NSDictionary *_Nonnull body;
@property (nonatomic, readonly) unsigned requestId;

- (nullable instancetype)init __attribute__((unavailable("Must use initWithAction:body:andRequestId: instead.")));
- (nullable instancetype)initWithAction:(enum rtm_action_t)action body:(NSDictionary *_Nonnull)body andRequestId:(unsigned)requestId;
- (nullable instancetype)initWithRawPdu:(char const *_Nonnull)pdu;


@end
