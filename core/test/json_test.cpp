#include <gtest/gtest.h>
#include <cstdint>
#include <rtm.h>
#include <rtm_internal.h>
#include <cstdlib> // alloca
#include <queue>
#include <vector>

struct subscription_data_t {
  std::string sub_id;
  std::string message;
};

struct rtm_wrapper_t {
  std::vector<char> rtm_data;
  rtm_client_t *rtm;

  rtm_wrapper_t() {
    rtm_data.resize(rtm_client_size);
    rtm = rtm_init(&rtm_data[0], rtm_default_pdu_handler, nullptr);
  }
} rtm_wrapper;

TEST(rtm_json, pdu_rtm_standard_response) {
  rtm_pdu_t pdu{};
  char json[] = R"({"action":"rtm/subscription/data","body":{"position":"1479315802:0","messages":["a",null,42 ]}})";
  rtm_parse_pdu(rtm_wrapper.rtm, json, &pdu);

  ASSERT_EQ(RTM_ACTION_SUBSCRIPTION_DATA, pdu.action);
  ASSERT_NOT_NULL(pdu.position);
  ASSERT_TRUE(0 == strcmp("1479315802:0", pdu.position));

  for (auto expected_message : {"\"a\"", "null", "42"}) {
      char *got_message = rtm_iterate(&pdu.message_iterator);
      ASSERT_STREQ(expected_message, got_message);
  }
}

TEST(rtm_json, pdu_field_in_random_order) {
  rtm_pdu_t pdu{};
  char json[] = R"({ "body" :  { "action" : "rtm/publish/error" , "id" : 12 , "body" : "foo"}, "action"    : "rtm/publish/ok" , "id" : 42 })";
  rtm_parse_pdu(rtm_wrapper.rtm, json, &pdu);

  ASSERT_EQ(RTM_ACTION_PUBLISH_OK, pdu.action);
  // ASSERT_TRUE(0 == strcmp(R"({ "action" : "rtm/publish/error" , "id" : 12 , "body" : "foo"})", pdu.body));
  ASSERT_EQ(42u, pdu.request_id);
}

TEST(rtm_json, pdu_body_is_absent) {
  rtm_pdu_t pdu{};
  char json[] = R"(  { "action" : "rtm/publish/ok" , "id" : 42  } )";
  rtm_parse_pdu(rtm_wrapper.rtm, json, &pdu);

  ASSERT_EQ(RTM_ACTION_PUBLISH_OK, pdu.action);
  ASSERT_TRUE(nullptr == pdu.body);
  ASSERT_EQ(42u, pdu.request_id);
}

TEST(rtm_json, pdu_action_is_absent) {
  rtm_pdu_t pdu{};
  char json[] = R"(  {    "id" : 42  ,"body":{"stuff":[1,2,null]}} )";
  rtm_parse_pdu(rtm_wrapper.rtm, json, &pdu);

  ASSERT_EQ(RTM_ACTION_UNKNOWN, pdu.action);
  ASSERT_STREQ(R"({"stuff":[1,2,null]})", pdu.body);
  ASSERT_EQ(42u, pdu.request_id);
}

TEST(rtm_json, pdu_empty_json) {
  rtm_pdu_t pdu{};
  char json[] = " {}";
  rtm_parse_pdu(rtm_wrapper.rtm, json, &pdu);

  ASSERT_EQ(RTM_ACTION_UNKNOWN, pdu.action);
  ASSERT_TRUE(nullptr == pdu.body);
  ASSERT_EQ(0u, pdu.request_id);
}

TEST(rtm_json, find_element) {
  char buf[128] = { 0 };
  strcpy(buf, R"({"messages": ["foo","bar","baz"]})");
  char *message = buf + 14;

  rtm_list_iterator_t iter;
  iter.position = message;

  ASSERT_EQ(*message, '"');

  message = rtm_iterate(&iter);
  ASSERT_EQ("\"foo\"", std::string(message));

  message = rtm_iterate(&iter);
  ASSERT_EQ("\"bar\"", std::string(message));

  message = rtm_iterate(&iter);
  ASSERT_EQ("\"baz\"", std::string(message));

  message = rtm_iterate(&iter);
  ASSERT_EQ(nullptr, message);
}

TEST(rtm_json, handle_invalid_json) {
  rtm_pdu_t pdu{};

  std::string invalids[] = {
    R"({"action":"rtm/subscription/data","body":[ 1,2,3 )",
    R"({"action":"rtm/subscription/data","body":[ 1,2,3 ]\" )",
    R"({"action":"rtm/subscription/data","body":[ 1,2,3 ],)",
    R"({"action":"rtm/subscription/data","body" {}})",
    R"({"action":"rtm/subscription/data","body":)",
    R"({"action":"rtm/subscription/data","body"})",
    R"({"action":"rtm/subscription/data","body":[ 1,2,3 }])",
    R"({"action":"rtm/subscription/data","body":{"a":[{}}]}})",
  };

  for(auto i : invalids) {
    std::string i_c = i;
    ASSERT_EQ(RTM_ERR_PROTOCOL, rtm_parse_pdu(rtm_wrapper.rtm, const_cast<char*>(i_c.c_str()), &pdu)) << "Input '" << i << "' went through";
  }
}

TEST(rtm_json, escape) {
  char buf[128] = { 0 };
  char *ret = nullptr;

  //simple string
  const char simple[] = "foo bar";
  ret = _rtm_json_escape(buf, 128, simple);
  ASSERT_EQ(strlen(simple), ret - buf);
  ASSERT_TRUE(0 == strcmp(buf, simple));

  // special characters
  ret = _rtm_json_escape(buf, 128, "\t \r \n \f \b \\ \" \x1c");
  ASSERT_TRUE(0 == strcmp(buf, "\\t \\r \\n \\f \\b \\\\ \\\" \\u001C"));
  ASSERT_EQ(27, ret - buf);

  // unicode string
  const char unicode_1[] = "Ǆ foo";
  ret = _rtm_json_escape(buf, 128, unicode_1);
  ASSERT_TRUE(0 == strcmp(buf, unicode_1));
  ASSERT_EQ(strlen(unicode_1), ret - buf);

  const char unicode_2[] = "௵ foo";
  ret = _rtm_json_escape(buf, 128, unicode_2);
  ASSERT_TRUE(0 == strcmp(buf, unicode_2));
  ASSERT_EQ(strlen(unicode_2), ret - buf);

  const char unicode_3[] = "😮 foo";
  ret = _rtm_json_escape(buf, 128, unicode_3);
  ASSERT_TRUE(0 == strcmp(buf, unicode_3));
  ASSERT_EQ(strlen(unicode_3), ret - buf);

  ret = _rtm_json_escape(buf, 0, "foo bar");
  ASSERT_EQ(nullptr, ret);

  // should abort
  ret = _rtm_json_escape(buf, 3, "foo bar");
  ASSERT_EQ(nullptr, ret);

  // should write 'foo\0'
  ret = _rtm_json_escape(buf, 4, "foo");
  ASSERT_TRUE(0 == strcmp(buf, "foo"));
  ASSERT_EQ(3, ret - buf);

  // should write 'foo\0'
  ret = _rtm_json_escape(buf, 5, "foo");
  ASSERT_TRUE(0 == strcmp(buf, "foo"));
  ASSERT_EQ(3, ret - buf);

  // should abort because \u001C is our of buffer but return the max buffer size
  ret = _rtm_json_escape(buf, 6, "foo \x1c");
  ASSERT_EQ(nullptr, ret);
}
