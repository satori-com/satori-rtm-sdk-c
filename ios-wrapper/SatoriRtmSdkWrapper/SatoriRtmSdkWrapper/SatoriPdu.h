#import <Foundation/Foundation.h>

@interface SatoriPdu : NSObject

@property (nonatomic, readonly) rtm_action_t action;
@property (nonatomic, readonly) id _Nonnull body;
@property (nonatomic, readonly) unsigned requestId;

- (nullable instancetype)init __attribute__((unavailable("Must use initWithAction:body:andRequestId: instead.")));
- (nullable instancetype)initWithAction:(nullable NSString*)action body:(nullable NSString*)body andRequestId:(unsigned)requestId;

@end
