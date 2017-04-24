#import <XCTest/XCTest.h>
#import "SatoriSDK.h"

// Add your API endpoint and appkey values here
// TODO: make these configurable
static NSString* const url = @"";
static NSString* const appkey = @"";
static NSString* const role_name = @"";

@interface SatoriSDKTests : XCTestCase {
    SatoriRtmConnection* rtmClient;
}
@end

@implementation SatoriSDKTests

- (void)setUp {
    [super setUp];
    
    XCTAssertTrue(url.length > 0);
    XCTAssertTrue(appkey.length > 0);
    
    rtmClient = [[SatoriRtmConnection alloc] initWithUrl:url andAppkey:appkey];
    XCTAssertNotNil(rtmClient, @"Initialization failed");
}

- (void)tearDown {
    [super tearDown];
    [rtmClient disconnect];
    rtmClient = nil;
}

- (void)testOpenConnection {
    rtm_status status = [rtmClient connect];
    XCTAssertEqual(status, RTM_OK, @"Failed to connect RTM");
}

- (void)testOpenConnectionWithCustomPdu {
    PduHandler handler = ^(SatoriPdu *pdu) {
        NSLog(@"%@", pdu.action);
    };
    
    rtmClient = [[SatoriRtmConnection alloc] initWithUrl:url andAppkey:appkey];
    rtm_status status = [rtmClient connectWithPduHandler:handler];
    XCTAssertEqual(status, RTM_OK, @"Failed to connect RTM");
}

- (void)testEnableVerboseLogging {
    XCTAssertFalse(rtmClient.enableVerboseLogging, @"Verbose logging should be disabled by default");

    rtm_status status = [rtmClient connect];
    XCTAssertEqual(status, RTM_OK, @"Failed to connect RTM");
    
    rtmClient.enableVerboseLogging = YES;
    XCTAssertTrue(rtmClient.enableVerboseLogging, @"Verbose logging should be enabled");

    rtmClient.enableVerboseLogging = NO;
    XCTAssertFalse(rtmClient.enableVerboseLogging, @"Verbose logging should be disabled");
}

- (void)testHandshake {
    rtm_status status = [rtmClient connect];
    XCTAssertEqual(status, RTM_OK, @"Failed to connect RTM");
    
    unsigned requestId;
    status = [rtmClient handshakeWithRole:role_name andRequestId:&requestId];
    XCTAssertEqual(status, RTM_OK, @"Failed to send handshake");
}

- (void)testPublishString {
    rtm_status status = [rtmClient connect];
    XCTAssertEqual(status, RTM_OK, @"Failed to connect RTM");
    
    status = [rtmClient publishString:@"Hello world" toChannel:@"test" andRequestId:0];
    XCTAssertEqual(status, RTM_OK, @"Failed to publish string");
}


- (void)testParsePduWithoutBody {
    NSString* jsonStr = @"{\"action\":\"rtm/publish/ok\", \"id\":42}";
    SatoriPdu* pdu = [SatoriRtmConnection parsePdu:jsonStr];
    XCTAssertNil(pdu);
}

- (void)testParsePduWithoutAction {
    NSString* jsonStr = @"{\"id\":42, \"body\":{\"position\":\"1479315802:0\",\"messages\":[\"a\",null,42]}}";
    SatoriPdu* pdu = [SatoriRtmConnection parsePdu:jsonStr];
    XCTAssertNil(pdu);
}

- (void)testParsePduWithEmptyJson {
    NSString* jsonStr = @"{}";
    SatoriPdu* pdu = [SatoriRtmConnection parsePdu:jsonStr];
    XCTAssertNil(pdu);
}

- (void)testParsePdu {
    NSString* jsonStr = @"{\"action\":\"rtm/publish/ok\", \"id\":42, \"body\":{\"position\":\"1479315802:0\",\"messages\":[\"a\",null,42]}}";
    SatoriPdu* pdu = [SatoriRtmConnection parsePdu:jsonStr];
    NSDictionary *expectedBody = @{@"position": @"1479315802:0", @"messages": @[@"a", [NSNull null], @(42)]};
    XCTAssertNotNil(pdu);
    XCTAssertEqualObjects(pdu.action, @"rtm/publish/ok", @"Failed to parse pdu action");
    XCTAssertEqualObjects(pdu.body[@"position"], expectedBody[@"position"], @"Failed to parse pdu body");
    XCTAssertEqualObjects(pdu.body[@"messages"], expectedBody[@"messages"], @"Failed to parse pdu body");
    XCTAssertEqual(pdu.requestId, 42, @"Failed to parse pdu requestId");
    XCTAssertEqualObjects(pdu.body[@"position"], @"1479315802:0", @"Failed to parse pdu body");
    XCTAssertEqual(((NSArray*)pdu.body[@"messages"]).count, 3, @"Failed to parse pdu body");
}

- (void)testParseSubscriptionData {
    rtm_status status = [rtmClient connect];
    XCTAssertEqual(status, RTM_OK, @"Failed to connect RTM");

    SatoriPdu* pdu = [[SatoriPdu alloc] initWithAction:@"rtm/subscription/data" body:@"{ \"messages\"   :   [\"a\",null,42],  \"subscription_id\"  :\"channel\"  }" andRequestId:42];

    NSArray *expectedMessages = @[@"a", [NSNull null], @(42)];
    XCTAssertEqualObjects(
        pdu.body[@"messages"],
        expectedMessages,
        @"Failed to parse messages correctly");
}

- (void)testPublishAndReceive {
    rtm_status status = [rtmClient connect];
    XCTAssertEqual(status, RTM_OK, @"Failed to connect RTM");

    unsigned int reqId;
    status = [rtmClient subscribe:@"temp" andRequestId:&reqId];
    XCTAssertEqual(status, RTM_OK, @"Failed to subscribe");
    
    status = [rtmClient publishString:@"Hello world" toChannel:@"temp" andRequestId:0];
    XCTAssertEqual(status, RTM_OK, @"Failed to publish");
    
    status = [rtmClient waitWithTimeout:15];
    XCTAssertEqual(status, RTM_OK, @"Failed to wait");
}

- (void)testPublishAndReceiveCustomPduHandler {
    __block int counter = 0;
    PduHandler handler = ^(SatoriPdu *pdu) {
        if (counter == 0) {
            XCTAssertEqualObjects(pdu.action, @"rtm/subscribe/ok");
        }
        if (counter == 1 || counter == 2) {
            XCTAssertEqualObjects(pdu.action, @"rtm/subscription/data");
        }
        counter++;
    };
    
    rtmClient = [[SatoriRtmConnection alloc] initWithUrl:url andAppkey:appkey];
    rtm_status status = [rtmClient connectWithPduHandler:handler];
    XCTAssertEqual(status, RTM_OK, @"Failed to connect RTM");
    
    unsigned int reqId;
    status = [rtmClient subscribe:@"temp" andRequestId:&reqId];
    XCTAssertEqual(status, RTM_OK, @"Failed to subscribe");
    
    for (int i=0; i < 3; i++) {
        status = [rtmClient publishString:@"Hello world" toChannel:@"temp" andRequestId:0];
        XCTAssertEqual(status, RTM_OK, @"Failed to publish");
        
        status = [rtmClient waitWithTimeout:15];
        XCTAssertEqual(status, RTM_OK, @"Failed to wait");
    }
}

- (void)testPublishAndReceiveJson {
    NSString* jsonStr = @"{\"key\":\"value\"}";
    
    __block int counter = 0;
    PduHandler handler = ^(SatoriPdu *pdu) {
        if (counter == 0) {
            XCTAssertEqualObjects(pdu.action, @"rtm/subscribe/ok");
        }
        if (counter == 1) {
            XCTAssertEqualObjects(pdu.action, @"rtm/subscription/data");
        }
        counter++;
    };
    
    rtmClient = [[SatoriRtmConnection alloc] initWithUrl:url andAppkey:appkey];
    rtm_status status = [rtmClient connectWithPduHandler:handler];
    XCTAssertEqual(status, RTM_OK, @"Failed to connect RTM");
    
    unsigned int reqId;
    status = [rtmClient subscribe:@"temp" andRequestId:&reqId];
    XCTAssertEqual(status, RTM_OK, @"Failed to subscribe");
    
    for (int i=0; i < 2; i++) {
        status = [rtmClient publishJson:jsonStr toChannel:@"temp" andRequestId:0];
        XCTAssertEqual(status, RTM_OK, @"Failed to publish");
        
        status = [rtmClient waitWithTimeout:15];
        XCTAssertEqual(status, RTM_OK, @"Failed to wait");
    }
}

- (void)testConnectionClose {
    rtm_status status = [rtmClient connect];
    XCTAssertEqual(status, RTM_OK, @"Failed to connect RTM");
    
    [rtmClient disconnect];
    
    uint requestId;
    status = [rtmClient subscribe:@"test" andRequestId:&requestId];
    XCTAssertGreaterThan(RTM_OK, status, @"Connection closed. Subscription should fail.");
}

@end
