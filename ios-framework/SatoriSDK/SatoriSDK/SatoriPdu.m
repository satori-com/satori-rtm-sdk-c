#import "SatoriPdu.h"

static id parseJsonObject(NSString *body) {
    if (body == nil) {
        return nil;
    }
    
    NSError *err = nil;
    id bodyObj = [NSJSONSerialization JSONObjectWithData:[body dataUsingEncoding:NSUTF8StringEncoding] options:NSJSONReadingAllowFragments error:&err];
    if (err != nil) {
        NSLog(@"Error deserializing body %@: %@", body, err);
        return nil;
    }
    return bodyObj;
}

@implementation SatoriPdu

- (instancetype)initWithAction:(NSString*)action body:(NSString*)body andRequestId:(unsigned)requestId {
    if (!action) {
        return nil;
    }

    id jsonBody = parseJsonObject(body);
    if (!jsonBody) {
        return nil;
    }

    self = [super init];
    if (self) {
        _action = action;
        _body = jsonBody;
        _requestId = requestId;
    }
    return self;
}

@end
