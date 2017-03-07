#include <gtest/gtest.h>
#include <cstdint>
#include <src/rtm_internal.h>
#include <cstdlib> // alloca
#include <queue>

struct subscription_data_t {
  std::string sub_id;
  std::string message;
};

void record_subscription_data(rtm_client_t* rtm, rtm_pdu_t& pdu) {
  size_t const size = 1024;
  char buf[size];
  rtm_parse_subscription_data(rtm, &pdu, buf, size,
      [](rtm_client_t *rtm, const char *sub_id, const char *message) {
        std::queue<subscription_data_t> *q = static_cast<std::queue<subscription_data_t> *>(rtm->user);
        subscription_data_t sub_data;
        sub_data.sub_id = sub_id ? std::string(sub_id) : "null";
        sub_data.message = message ? std::string(message) : "null";
        q->push(sub_data);
      });
}

rtm_client_t *rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));

TEST(rtm_json, pdu_rtm_standard_response) {
  rtm_pdu_t pdu{};
  char json[] = R"({"action":"rtm/publish/ok","id":42,"body":{"next":"1479315802:0","messages":[ "a", null, 42 ]}})";
  rtm_parse_pdu(json, &pdu);

  ASSERT_TRUE(0 == strcmp("rtm/publish/ok", pdu.action));
  ASSERT_TRUE(0 == strcmp(R"({"next":"1479315802:0","messages":[ "a", null, 42 ]})", pdu.body));
  ASSERT_EQ(42, pdu.request_id);
}

TEST(rtm_json, pdu_field_in_random_order) {
  rtm_pdu_t pdu{};
  char json[] = R"({ "body" :  { "action" : "rtm/publish/error" , "id" : 12 , "body" : "foo"}, "action"    : "rtm/publish/ok" , "id" : 42 })";
  rtm_parse_pdu(json, &pdu);

  ASSERT_TRUE(0 == strcmp("rtm/publish/ok", pdu.action));
  ASSERT_TRUE(0 == strcmp(R"({ "action" : "rtm/publish/error" , "id" : 12 , "body" : "foo"})", pdu.body));
  ASSERT_EQ(42, pdu.request_id);
}

TEST(rtm_json, pdu_body_is_absent) {
  rtm_pdu_t pdu{};
  char json[] = R"(  { "action" : "rtm/publish/ok" , "id" : 42  } )";
  rtm_parse_pdu(json, &pdu);

  ASSERT_TRUE(0 == strcmp("rtm/publish/ok", pdu.action));
  ASSERT_TRUE(nullptr == pdu.body);
  ASSERT_EQ(42, pdu.request_id);
}

TEST(rtm_json, pdu_action_is_absent) {
  rtm_pdu_t pdu{};
  char json[] = R"(  {    "id" : 42  } )";
  rtm_parse_pdu(json, &pdu);

  ASSERT_TRUE(nullptr == pdu.action);
  ASSERT_TRUE(nullptr == pdu.body);
  ASSERT_EQ(42, pdu.request_id);
}

TEST(rtm_json, pdu_empty_json) {
  rtm_pdu_t pdu{};
  char json[] = " {}";
  rtm_parse_pdu(json, &pdu);

  ASSERT_TRUE(nullptr == pdu.action);
  ASSERT_TRUE(nullptr == pdu.body);
  ASSERT_EQ(0, pdu.request_id);
}

TEST(rtm_json, subscription_data) {
  std::queue<subscription_data_t> message_queue;
  rtm_client_t *rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  rtm->user = &message_queue;

  rtm_pdu_t pdu{};
  pdu.action = "rtm/subscription/data";
  pdu.body = R"({"next":"1479315802:0","messages":[ "a", null, 42, {} ],"subscription_id":"channel"})";
  record_subscription_data(rtm, pdu);

  ASSERT_FALSE(message_queue.empty());
  ASSERT_EQ("channel", message_queue.front().sub_id);
  ASSERT_EQ(R"("a")", message_queue.front().message);
  message_queue.pop();

  ASSERT_FALSE(message_queue.empty());
  ASSERT_EQ("channel", message_queue.front().sub_id);
  ASSERT_EQ("null", message_queue.front().message);
  message_queue.pop();

  ASSERT_FALSE(message_queue.empty());
  ASSERT_EQ("channel", message_queue.front().sub_id);
  ASSERT_EQ("42", message_queue.front().message);
  message_queue.pop();

  ASSERT_FALSE(message_queue.empty());
  ASSERT_EQ("channel", message_queue.front().sub_id);
  ASSERT_EQ("{}", message_queue.front().message);
  message_queue.pop();

  ASSERT_TRUE(message_queue.empty());

  pdu.body = R"(  { "messages"   :   [ "foobar" ],  "subscription_id"  :"channel"  })";
  record_subscription_data(rtm, pdu);

  ASSERT_FALSE(message_queue.empty());
  ASSERT_EQ("channel", message_queue.front().sub_id);
  ASSERT_EQ(R"("foobar")", message_queue.front().message);
  message_queue.pop();
  ASSERT_TRUE(message_queue.empty());

  pdu.body = R"(  {  "subscription_id"  :"channel",  "messages"   :   [  ]  })";
  record_subscription_data(rtm, pdu);
  ASSERT_TRUE(message_queue.empty());

  pdu.body = R"({"subscription_id":"channel","messages":[]})";
  record_subscription_data(rtm, pdu);
  ASSERT_TRUE(message_queue.empty());

  pdu.body = R"({"messages":[{"subscription_id":"another_channel"}],"subscription_id":"channel-2"})";
  record_subscription_data(rtm, pdu);

  ASSERT_FALSE(message_queue.empty());
  ASSERT_EQ("channel-2", message_queue.front().sub_id);
  ASSERT_EQ(R"({"subscription_id":"another_channel"})", message_queue.front().message);
  message_queue.pop();
  ASSERT_TRUE(message_queue.empty());
}

TEST(rtm_json, escape) {
  char buf[128] = { 0 };
  int ret = 0;

  //simple string
  const char simple[] = "foo bar";
  ret = _rtm_json_escape(buf, 128, simple);
  ASSERT_EQ(strlen(simple), ret);
  ASSERT_TRUE(0 == strcmp(buf, simple));

  // special characters
  ret = _rtm_json_escape(buf, 128, "\t \r \n \f \b \\ \" \x1c");
  ASSERT_TRUE(0 == strcmp(buf, "\\t \\r \\n \\f \\b \\\\ \\\" \\u001C"));
  ASSERT_EQ(27, ret);

  // unicode string 
  const char unicode_1[] = "Ǆ foo";
  ret = _rtm_json_escape(buf, 128, unicode_1);
  ASSERT_TRUE(0 == strcmp(buf, unicode_1));
  ASSERT_EQ(strlen(unicode_1), ret);

  const char unicode_2[] = "௵ foo";
  ret = _rtm_json_escape(buf, 128, unicode_2);
  ASSERT_TRUE(0 == strcmp(buf, unicode_2));
  ASSERT_EQ(strlen(unicode_2), ret);

  const char unicode_3[] = "😮 foo";
  ret = _rtm_json_escape(buf, 128, unicode_3);
  ASSERT_TRUE(0 == strcmp(buf, unicode_3));
  ASSERT_EQ(strlen(unicode_3), ret);

  ret = _rtm_json_escape(buf, -1, "foo bar");
  ASSERT_EQ(0, ret);

  ret = _rtm_json_escape(buf, 0, "foo bar");
  ASSERT_EQ(0, ret);

  // should write 'fo\0'
  ret = _rtm_json_escape(buf, 3, "foo bar");
  ASSERT_TRUE(0 == strcmp(buf, "fo"));
  ASSERT_EQ(3, ret);

  // should write 'foo\0'
  ret = _rtm_json_escape(buf, 4, "foo");
  ASSERT_TRUE(0 == strcmp(buf, "foo"));
  ASSERT_EQ(3, ret);

  // should write 'foo\0'
  ret = _rtm_json_escape(buf, 5, "foo");
  ASSERT_TRUE(0 == strcmp(buf, "foo"));
  ASSERT_EQ(3, ret);

  // should write 'foo \0' because \u001C is our of buffer but return the max buffer size
  ret = _rtm_json_escape(buf, 6, "foo \x1c");
  ASSERT_TRUE(0 == strcmp(buf, "foo "));
  ASSERT_EQ(6, ret);
}
