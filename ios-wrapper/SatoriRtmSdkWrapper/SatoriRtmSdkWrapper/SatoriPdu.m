#import "SatoriPdu.h"


@implementation SatoriPdu

- (instancetype)initWithAction:(enum rtm_action_t)action body:(NSDictionary*)body andRequestId:(unsigned)requestId {
    self = [super init];
    if (self) {
        _action = action;
        _body = body;
        _requestId = requestId;
    }
    return self;
}

- (instancetype)initWithRawPdu:(char const *)pdu
{
    self = [super init];
    if (!self) {
        return nil;
    }

    static NSDictionary *actionTable = nil;
    if (!actionTable) {
        actionTable = @{
            @"/error": @(RTM_ACTION_GENERAL_ERROR),
            @"auth/authenticate/error": @(RTM_ACTION_AUTHENTICATE_ERROR),
            @"auth/authenticate/ok": @(RTM_ACTION_AUTHENTICATE_OK),
            @"rtm/delete/error": @(RTM_ACTION_DELETE_ERROR),
            @"rtm/delete/ok": @(RTM_ACTION_DELETE_OK),
            @"auth/handshake/error": @(RTM_ACTION_HANDSHAKE_ERROR),
            @"auth/handshake/ok": @(RTM_ACTION_HANDSHAKE_OK),
            @"rtm/publish/error": @(RTM_ACTION_PUBLISH_ERROR),
            @"rtm/publish/ok": @(RTM_ACTION_PUBLISH_OK),
            @"rtm/read/error": @(RTM_ACTION_READ_ERROR),
            @"rtm/read/ok": @(RTM_ACTION_READ_OK),
            @"rtm/subscribe/error": @(RTM_ACTION_SUBSCRIBE_ERROR),
            @"rtm/subscribe/ok": @(RTM_ACTION_SUBSCRIBE_OK),
            @"rtm/subscription/data": @(RTM_ACTION_SUBSCRIPTION_DATA),
            @"rtm/subscription/info": @(RTM_ACTION_SUBSCRIPTION_INFO),
            @"rtm/subscription/error": @(RTM_ACTION_SUBSCRIPTION_ERROR),
            @"rtm/unsubscribe/error": @(RTM_ACTION_UNSUBSCRIBE_ERROR),
            @"rtm/unsubscribe/ok": @(RTM_ACTION_UNSUBSCRIBE_OK),
            @"rtm/write/error": @(RTM_ACTION_WRITE_ERROR),
            @"rtm/write/ok": @(RTM_ACTION_WRITE_OK)
        };
    }

    NSDictionary *pdu_json = [NSJSONSerialization
        JSONObjectWithData:[NSData dataWithBytes:pdu length:strlen(pdu)]
        options:0
        error:nil];

    _body = [pdu_json objectForKey:@"body"];
    if (!_body) {
        _body = @{};
    }

    _requestId = [[pdu_json objectForKey:@"id"] intValue];
    _action = [[actionTable objectForKey:pdu_json[@"action"]] intValue];

    return self;
}

@end
