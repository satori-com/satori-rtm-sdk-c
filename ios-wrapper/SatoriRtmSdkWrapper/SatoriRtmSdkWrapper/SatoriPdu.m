#import "SatoriPdu.h"

@implementation SatoriPdu

- (instancetype)initWithAction:(enum rtm_action_t)action fields:(NSDictionary*)fields andRequestId:(unsigned)requestId {
    self = [super init];
    if (self) {
        _action = action;
        _fields = fields;
        _requestId = requestId;
    }
    return self;
}

- (instancetype)initWithLowLevelPdu:(const rtm_pdu_t *)pdu
{
    NSMutableDictionary *fields = [NSMutableDictionary new];
    void (^addStringField)(NSString *, char const *) = ^(NSString *field_name, char const *s) {
        if (!s) {
            return;
        }
        fields[field_name] = [NSString stringWithUTF8String:s];

    };
    void (^addJSONField)(NSString *, char const *) = ^(NSString *field_name, char const *s) {
        if (!s) {
            return;
        }
        fields[field_name] = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:s length:strlen(s)] options:NSJSONReadingAllowFragments error:nil];
    };
    switch (pdu->action) {
        case RTM_ACTION_AUTHENTICATE_ERROR:
        case RTM_ACTION_DELETE_ERROR:
        case RTM_ACTION_HANDSHAKE_ERROR:
        case RTM_ACTION_PUBLISH_ERROR:
        case RTM_ACTION_READ_ERROR:
        case RTM_ACTION_SEARCH_ERROR:
        case RTM_ACTION_SUBSCRIBE_ERROR:
        case RTM_ACTION_UNSUBSCRIBE_ERROR:
        case RTM_ACTION_WRITE_ERROR:
            addStringField(@"error", pdu->error);
            addStringField(@"reason", pdu->reason);
            break;
        case RTM_ACTION_HANDSHAKE_OK:
            addStringField(@"nonce", pdu->nonce);
            break;
        case RTM_ACTION_PUBLISH_OK:
        case RTM_ACTION_DELETE_OK:
        case RTM_ACTION_WRITE_OK:
            addStringField(@"position", pdu->position);
            break;
        case RTM_ACTION_SUBSCRIBE_OK:
        case RTM_ACTION_UNSUBSCRIBE_OK:
            addStringField(@"position", pdu->position);
            addStringField(@"subscription_id", pdu->subscription_id);
            break;
        case RTM_ACTION_READ_OK:
            addStringField(@"position", pdu->position);
            addJSONField(@"message", pdu->message);
            break;
        case RTM_ACTION_AUTHENTICATE_OK:
            break;
        case RTM_ACTION_SUBSCRIPTION_DATA:
            addStringField(@"position", pdu->position);
            addStringField(@"subscription_id", pdu->subscription_id);
            fields[@"messages"] = [NSMutableArray new];
            char *message;
            while ((message = rtm_iterate(&pdu->message_iterator))) {
                id object = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:message length:strlen(message)] options:NSJSONReadingAllowFragments error:nil];
                if (object) {
                    [fields[@"messages"] addObject:object];
                }
            }
            break;
        case RTM_ACTION_SEARCH_DATA: // search results are parsed elsewhere
        case RTM_ACTION_SEARCH_OK:
            fields[@"results"] = [NSMutableArray new];
            char *channel;
            while ((channel = rtm_iterate(&pdu->channel_iterator))) {
                id object = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:channel length:strlen(channel)] options:NSJSONReadingAllowFragments error:nil];
                if (object) {
                    [fields[@"results"] addObject:object];
                }
            }
            break;
        case RTM_ACTION_UNKNOWN: {
            if (pdu->body) {
                id body = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:pdu->body length:strlen(pdu->body)] options:NSJSONReadingAllowFragments error:nil];
                if (body) {
                    fields[@"body"] = body;
                }
            }
            break;
        }
        case RTM_ACTION_SENTINEL:
            assert(0); // Should never happen
    }
    return [[SatoriPdu alloc] initWithAction:pdu->action fields:fields andRequestId:pdu->request_id];
}

@end
