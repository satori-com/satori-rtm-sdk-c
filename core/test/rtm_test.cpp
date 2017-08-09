#include <gtest/gtest.h>
#include <queue>
#include <chrono>
#include <cstdint>
#include <cstdlib> // alloca
#include <ctime>
#include <vector>

#ifdef _WIN32
#include <WinSock2.h>
#include <Windows.h>
#include <WS2tcpip.h>
#endif

#include <nlohmann_json/json.hpp>

#include <src/rtm.h>
#include "config.h"
#include "rtm_internal.h"

using json = nlohmann::json;

struct event_t {
  unsigned request_id = 0;
  rtm_action_t action;
  std::string info;
};

std::queue<event_t> event_queue;
std::queue<std::string> message_queue;

void pdu_recorder(rtm_client_t *rtm, const rtm_pdu_t *pdu) {
  event_t event;
  event.action = pdu->action;
  event.request_id = pdu->request_id;
  switch (event.action) {
    case RTM_ACTION_AUTHENTICATE_ERROR:
    case RTM_ACTION_DELETE_ERROR:
    case RTM_ACTION_HANDSHAKE_ERROR:
    case RTM_ACTION_PUBLISH_ERROR:
    case RTM_ACTION_READ_ERROR:
    case RTM_ACTION_SEARCH_ERROR:
    case RTM_ACTION_SUBSCRIBE_ERROR:
    case RTM_ACTION_UNSUBSCRIBE_ERROR:
    case RTM_ACTION_WRITE_ERROR:
      event.info = std::string(pdu->error);
      break;
    case RTM_ACTION_HANDSHAKE_OK:
      event.info = std::string(pdu->nonce);
      break;
    case RTM_ACTION_SUBSCRIBE_OK:
    case RTM_ACTION_UNSUBSCRIBE_OK: {
      event.info = std::string(pdu->subscription_id);
      break;
    }
    case RTM_ACTION_READ_OK:
      event.info = std::string(pdu->message);
      break;
    case RTM_ACTION_UNKNOWN:
      event.info = std::string(pdu->body);
      break;
    case RTM_ACTION_SUBSCRIPTION_DATA: {
      char *message;
      while ((message = rtm_iterate(&pdu->message_iterator))) {
        event_t data = event;
        data.info = std::string(pdu->subscription_id) + ":" + std::string(message);
        event_queue.push(data);
      }
      return;
    }
    case RTM_ACTION_SEARCH_OK:
    case RTM_ACTION_SEARCH_DATA: {
      char *channel;
      while ((channel = rtm_iterate(&pdu->channel_iterator))) {
        event_t data = event;
        data.action = RTM_ACTION_SEARCH_DATA;
        data.info = std::string(channel);
        event_queue.push(data);
      }
      if (RTM_ACTION_SEARCH_DATA == event.action) {
        return;
      }
      break;
    }
    default:
      event.info = "";
      break;
  }
  event_queue.push(event);
}

void raw_pdu_recorder(rtm_client_t *rtm, char const *raw_pdu) {
  event_t event{};
  event.info = std::string(raw_pdu);
  event_queue.push(event);
}


rtm_status next_event(rtm_client_t *rtm, event_t* event) {
  rtm_status rc = RTM_OK;
  while (event_queue.size() == 0 && rc == RTM_OK) {
    rc = rtm_wait_timeout(rtm, 15);
  }
  if (event_queue.size() != 0) {
    *event = event_queue.front();
    event_queue.pop();
  }
  return rc;
}

static std::string make_channel(int len = 6) {
  std::string r = "";
  for (; len > 0; --len) {
    r += static_cast<char>(static_cast<int>('a') + rand() % 26);
  }
  return r;
}

TEST(rtm_test, subscribe) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, rtm_default_pdu_handler, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  std::string const channel = make_channel();
  rc = rtm_subscribe(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while subscribe to channel";
  rtm_close(rtm);
}

TEST(rtm_test, publish_and_subscribe_with_history) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();
  rc = rtm_publish_string(rtm, channel.c_str(), "my message", &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publishing";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ(RTM_ACTION_PUBLISH_OK, event.action);

  std::string const body = R"({"channel":")" + channel + R"(","history":{"count":1}})";
  rc = rtm_subscribe_with_body(rtm, body.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while subscribing";

  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ(RTM_ACTION_SUBSCRIBE_OK, event.action);
  ASSERT_EQ(channel, event.info);

  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ(RTM_ACTION_SUBSCRIPTION_DATA, event.action);
  ASSERT_EQ(channel + ":" + R"("my message")", event.info);

  rtm_close(rtm);
}

TEST(rtm_test, connect_ssl) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  rtm_close(rtm);
}

TEST(rtm_test, publish) {
  void *memory = alloca(rtm_client_size);

  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  std::string const channel = make_channel();
  rc = rtm_publish_string(rtm, channel.c_str(), "my message", nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publish to channel";

  rtm_close(rtm);
}

TEST(rtm_test, overflow) {
  void *memory = alloca(rtm_client_size);

  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  std::string const channel = make_channel();

  std::string big_body(16 * 1024 * 1024, 'a');
  rc = rtm_subscribe_with_body(rtm, big_body.c_str(), nullptr);
  ASSERT_EQ(RTM_ERR_OOM, rc)<< "Expected rtm_subscribe_with_body to fail";

  rtm_close(rtm);
}

TEST(rtm_test, publish_json_and_read) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);

  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();
  const std::string msg = R"({"foo":"bar"})";
  rc = rtm_publish_json(rtm, channel.c_str(), msg.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publish to channel";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ(RTM_ACTION_PUBLISH_OK, event.action);

  rc = rtm_read(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publish to channel";

  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait event";
  ASSERT_EQ(RTM_ACTION_READ_OK, event.action);
  ASSERT_EQ(msg, event.info);

  rtm_close(rtm);
}

TEST(rtm_test, read_write_delete) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);

  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();

  rc = rtm_read(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publish to channel";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ(RTM_ACTION_READ_OK, event.action);
  ASSERT_EQ(request_id, event.request_id);
  ASSERT_EQ("null", event.info);


  rc = rtm_write_string(rtm, channel.c_str(), "msg", &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while write";

  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ(RTM_ACTION_WRITE_OK, event.action);

  rc = rtm_read(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while read";

  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ(RTM_ACTION_READ_OK, event.action);
  ASSERT_EQ(request_id, event.request_id);
  ASSERT_EQ("\"msg\"", event.info);

  rc = rtm_delete(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while delete";

  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ(RTM_ACTION_DELETE_OK, event.action);

  rc = rtm_read(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while read";

  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ(RTM_ACTION_READ_OK, event.action);
  ASSERT_EQ(request_id, event.request_id);
  ASSERT_EQ("null", event.info);

  rtm_close(rtm);
}

TEST(rtm_test, handshake_and_authenticate) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  rc = rtm_handshake(rtm, role_name, &request_id);
  ASSERT_EQ(rc, RTM_OK) << "Failed to send rtm/handshake";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ(RTM_ACTION_HANDSHAKE_OK, event.action);
  std::string nonce = event.info;
  rc = rtm_authenticate(rtm, role_secret, nonce.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to send auth/authenticate";

   rc = next_event(rtm, &event);
   ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
   ASSERT_EQ(RTM_ACTION_AUTHENTICATE_OK, event.action);

  rtm_close(rtm);
}

TEST(rtm_test, publish_and_receive) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();
  rc = rtm_subscribe(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(rc, RTM_OK) << "Failed to subscribe";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ(RTM_ACTION_SUBSCRIBE_OK, event.action);
  ASSERT_EQ(channel, event.info);

  rc = rtm_publish_string(rtm, channel.c_str(), "my message", nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publishing";

  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ(RTM_ACTION_SUBSCRIPTION_DATA, event.action);
  ASSERT_EQ(channel + ":" + R"("my message")", event.info);

  rtm_close(rtm);
}

TEST(rtm_test, publish_ws_frame_with_126_bytes_payload) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  // channel is hardcoded with fixed length to get 126 bytes payload for WS frame
  unsigned int request_id;
  rc = rtm_publish_json(rtm, "xxxxxxxxxxxxxxx", "{\n   \"cmd_data\" : \"1\",\n   \"cmd_type\" : \"ack\"\n}\n", &request_id);
  ASSERT_EQ(RTM_OK, rc) << "Failed while publishing";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait publish response";
  ASSERT_EQ(RTM_ACTION_PUBLISH_OK, event.action);

  rtm_close(rtm);
}

TEST(rtm_test, disconnect) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  rtm_close(rtm);
  std::string const channel = make_channel();
  rc = rtm_subscribe(rtm, channel.c_str(), &request_id);
  ASSERT_GT(RTM_OK, rc)<< "Susbcription succeeded, but RTM should have been closed";
}

TEST(rtm_test, rtm_poll_does_not_hang_ssl) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  ASSERT_EQ(RTM_WOULD_BLOCK, rtm_poll(rtm)) << "Failed to poll";

  rtm_close(rtm);
}


TEST(rtm_test, rtm_poll_does_not_hang_nossl) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  ASSERT_EQ(RTM_WOULD_BLOCK, rtm_poll(rtm)) << "Failed to poll";

  rtm_close(rtm);
}

TEST(rtm_test, rtm_wait_timeout) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  time_t before = time(nullptr);
  rc = rtm_wait_timeout(rtm, 2);
  time_t after = time(nullptr);

  ASSERT_EQ(RTM_ERR_TIMEOUT, rc) << "rtm_wait_timeout failed to report timeout";
  ASSERT_GT(after - before, 1) << "rtm_wait_timeout returned too quickly";
  ASSERT_LT(after - before, 4) << "rtm_wait_timeout returned too slowly";

  rtm_close(rtm);
}

TEST(rtm_test, verbose_logging) {
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));

  rtm_disable_verbose_logging(rtm);
  ASSERT_EQ(rtm->is_verbose, 0u) << "verbose_logging Unable to disable verbose loggin";

  rtm_enable_verbose_logging(rtm);
  ASSERT_EQ(rtm->is_verbose, 1u) << "verbose_logging Unable to enable verbose loggin";
}

TEST(rtm_test, log_message) {
  const char *str = "Test log";

  rtm_status status = _rtm_log_message(RTM_OK, str);
  ASSERT_EQ(status, RTM_OK);
}

TEST(rtm_test, unsubscribe) {
  unsigned int request_id;

  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  std::string const channel = make_channel();
  rc = rtm_subscribe(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while subscribing to channel";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait subscribe response";
  ASSERT_EQ(RTM_ACTION_SUBSCRIBE_OK, event.action);
  ASSERT_EQ(channel, event.info);

  rc = rtm_unsubscribe(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while unsubscribing from channel";

  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait unsibscribe response";
  ASSERT_EQ(RTM_ACTION_UNSUBSCRIBE_OK, event.action);
  ASSERT_EQ(channel, event.info);

  rtm_close(rtm);
}

TEST(rtm_test, check_rtm_fd) {
  int fd;
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  fd = rtm_get_fd(rtm);
  ASSERT_GT(fd, 0);

  rtm_close(rtm);
  fd = rtm_get_fd(rtm);
  ASSERT_EQ(fd, -1);
}

TEST(rtm_test, get_user_context) {
  struct u_context {
    int user_id;
    char *data;
  };

  u_context context = {12, (char *)"Hello"};

  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, &context);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  u_context *rtm_context = static_cast<u_context *>(rtm_get_user_context(rtm));
  ASSERT_EQ(context.user_id, rtm_context->user_id);
  ASSERT_EQ(context.data, rtm_context->data);

  rtm_close(rtm);
}

TEST(rtm_test, raw_pdu_handler) {
  std::string const channel = make_channel();
  void *memory = alloca(rtm_client_size);

  rtm_client_t *rtm = rtm_init(memory, rtm_default_pdu_handler, nullptr);
  rtm_set_raw_pdu_handler(rtm, raw_pdu_recorder);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  unsigned int request_id;
  rc = rtm_write_string(rtm, channel.c_str(), "publish_msg", &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while write";
  
  rc = rtm_wait_timeout(rtm, 15);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while waiting rtm response";

  event_t event;
  rc = next_event(rtm, &event);

  ASSERT_LE(event.info.find(R"("action":"rtm/write/ok")"), std::string::npos);
  ASSERT_LE(event.info.find(R"("id":1)"), std::string::npos);

  ASSERT_EQ(RTM_OK, rc);
  rtm_close(rtm);
}

TEST(rtm_test, rtm_default_pdu_handler) {
  unsigned int request_id;
  std::string const channel = make_channel();
  void *memory = alloca(rtm_client_size);

  rtm_client_t *rtm = rtm_init(memory, rtm_default_pdu_handler, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  rc = rtm_write_string(rtm, channel.c_str(), "publish_msg", &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while write";
  
  rc = rtm_wait_timeout(rtm, 15);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while waiting rtm response";
  rtm_close(rtm);
}

TEST(rtm_test, read_with_body) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);

  std::string const channel = make_channel();

  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const body = R"({"channel":")" + channel + R"("})";

  // Read from the non-existing channel
  rc = rtm_read_with_body(rtm, body.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to read with body";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc) << "Failed to get next PDU";
  ASSERT_EQ(RTM_ACTION_READ_OK, event.action);
  ASSERT_EQ("null", event.info);

  // Publish 3 messages
  for (int i = 0; i < 3; i++) {
    std::string message = "message-" + std::to_string(i);
    rc = rtm_publish_string(rtm, channel.c_str(), message.c_str(), &request_id);
    ASSERT_EQ(RTM_OK, rc)<< "Failed while write";
    rc = next_event(rtm, &event);
    ASSERT_EQ(RTM_OK, rc) << "Failed to get next PDU";
    ASSERT_EQ(RTM_ACTION_PUBLISH_OK, event.action);
  }

  rc = rtm_read_with_body(rtm, body.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to read with body";

  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc) << "Failed to get next event";
  ASSERT_EQ(RTM_ACTION_READ_OK, event.action);
  ASSERT_EQ("\"message-2\"", event.info);

  rtm_close(rtm);
}

TEST(rtm_test, rtm_write_json) {
  json test_json;
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);
  std::string const channel = make_channel();

  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  test_json["intval"] = 12345;
  test_json["bool"] = true;
  test_json["list"] = {1, 2, 3};
  test_json["object"] = {{"currency", "USD"}, {"value", 42.99}};

  rtm_write_json(rtm, channel.c_str(), test_json.dump().c_str(), &request_id);
  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc) << "Failed to get next PDU";
  ASSERT_EQ(RTM_ACTION_WRITE_OK, event.action);

  rtm_read(rtm, channel.c_str(), &request_id);
  rc = next_event(rtm, &event);
  ASSERT_EQ(RTM_OK, rc) << "Failed to get next PDU";
  ASSERT_EQ(RTM_ACTION_READ_OK, event.action);
  ASSERT_EQ(test_json, json::parse(event.info));

  rtm_close(rtm);
}

TEST(rtm_test, publish_and_receive_all_json_types) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();
  rc = rtm_subscribe(rtm, channel.c_str(), &request_id);

  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ(RTM_ACTION_SUBSCRIBE_OK, event.action);
  ASSERT_EQ(channel, event.info);

  char const *messages[] =
      {"null", "42",
       // FIXME: Uncomment this case when serverside is fixed
       // "3.14159",
       R"("")", R"("hello")", "[]", "{}", "[null]", "[42]",
       "[3.14159]", R"(["\""])", R"(["hello"])",
       R"({"key":null})", R"({"key":42})", R"({"key":3.14159})",
       R"({"key":""})", R"({"key":"hello"})",
       R"({"key":[]})", R"({"key":{}})",
       R"({"key":[42, "foo"]})", R"({"key":{"foo": 42}})",
       R"([{}, null, {"key":"value"}, null])",
      };

  for (char const *message : messages) {
      ASSERT_EQ(RTM_OK, rtm_publish_json(rtm, channel.c_str(), message, nullptr));

      rc = next_event(rtm, &event);
      ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
      ASSERT_EQ(RTM_ACTION_SUBSCRIPTION_DATA, event.action);
      ASSERT_EQ(channel + ":" + std::string(message), event.info);
  }

  rtm_close(rtm);
}

TEST(rtm_test, DISABLED_rtm_search_test) {
  unsigned int request_id;
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();
  rc = rtm_publish_string(rtm, channel.c_str(), "test", &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to send a publish request";

  event_t event;
  rc = next_event(rtm, &event);
  ASSERT_EQ(rc, RTM_OK) << "Failed to receive an ack";
  ASSERT_EQ(RTM_ACTION_PUBLISH_OK, event.action);

  rc = rtm_search(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(rc, RTM_OK) << "Failed to send a search request";

  std::vector<std::string> channels;

  do {
    rc = next_event(rtm, &event);
    ASSERT_EQ(RTM_OK, rc) << "Failed to receive PDU";
    ASSERT_TRUE((RTM_ACTION_SEARCH_DATA == event.action) || (RTM_ACTION_SEARCH_OK == event.action));
    if (RTM_ACTION_SEARCH_DATA == event.action) {
      std::string name = json::parse(event.info).get<std::string>();
      channels.push_back(name);
    }
  } while (RTM_ACTION_SEARCH_OK != event.action);


  bool found = channels.end() != std::find(channels.begin(), channels.end(), channel);
  ASSERT_EQ(true, found) << "rtm/search failed to find our channel";
}

TEST(rtm_test, parse_endpoint_test) {
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));

  char hostname[255];
  char port[10];
  char path[255];
  unsigned use_tls;
  rtm_status rc;

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "wss://example.com/", (enum rtm_url_scheme_t)(SCHEME_WSS | SCHEME_WS), hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("443", std::string(port));
  ASSERT_EQ("/", std::string(path));
  ASSERT_EQ(1u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "ws://example.com/", (enum rtm_url_scheme_t)(SCHEME_WS | SCHEME_WSS), hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("80", std::string(port));
  ASSERT_EQ("/", std::string(path));
  ASSERT_EQ(0u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(rtm, "ws://example.com", SCHEME_WS, hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("80", std::string(port));
  ASSERT_EQ("/", std::string(path));
  ASSERT_EQ(0u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "ws://example.com/v3", SCHEME_WS, hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("80", std::string(port));
  ASSERT_EQ("/v3", std::string(path));
  ASSERT_EQ(0u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "ws://example.com:8080/v3", SCHEME_WS, hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("8080", std::string(port));
  ASSERT_EQ("/v3", std::string(path));
  ASSERT_EQ(0u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "wss://example.com:8080/foo/bar/", SCHEME_WSS, hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("8080", std::string(port));
  ASSERT_EQ("/foo/bar/", std::string(path));
  ASSERT_EQ(1u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "wss://example.com:8080/foo/bar", SCHEME_WSS, hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("8080", std::string(port));
  ASSERT_EQ("/foo/bar", std::string(path));
  ASSERT_EQ(1u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "http://proxy.proxy:7711", SCHEME_HTTP, hostname, port, path, &use_tls);
  ASSERT_EQ("proxy.proxy", std::string(hostname));
  ASSERT_EQ("7711", std::string(port));
  ASSERT_EQ(0u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "http://proxy.proxy", SCHEME_HTTP, hostname, port, path, &use_tls);
  ASSERT_EQ("proxy.proxy", std::string(hostname));
  ASSERT_EQ("80", std::string(port));
  ASSERT_EQ(0u, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(
      rtm, "wss://example.com:8080/foo/bar", SCHEME_HTTP, hostname, port, path, &use_tls);
  ASSERT_EQ(RTM_ERR_PROTOCOL, rc);

  rc = _rtm_test_parse_endpoint(
      rtm, "http://example.com:8080/foo/bar", (enum rtm_url_scheme_t)(SCHEME_WS | SCHEME_WSS), hostname, port, path, &use_tls);
  ASSERT_EQ(RTM_ERR_PROTOCOL, rc);

  rc = _rtm_test_parse_endpoint(
      rtm, "ws://example.com:8080/foo/bar", SCHEME_HTTP, hostname, port, path, &use_tls);
  ASSERT_EQ(RTM_ERR_PROTOCOL, rc);

  rc = _rtm_test_parse_endpoint(
      rtm, "https://example.com:8080/foo/bar", SCHEME_HTTP, hostname, port, path, &use_tls);
  ASSERT_EQ(RTM_ERR_PROTOCOL, rc);
}

TEST(rtm_test, prepare_path_test) {
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  char path[255];
  rtm_status rc;

  strncpy(path, "/", sizeof(path));
  rc = _rtm_test_prepare_path(rtm, path, "zzzzzz");
  ASSERT_EQ(RTM_OK, rc);
  ASSERT_EQ("/v2?appkey=zzzzzz", std::string(path));

  strncpy(path, "/foo/bar", sizeof(path));
  rc = _rtm_test_prepare_path(rtm, path, "zzzzzz");
  ASSERT_EQ(RTM_OK, rc);
  ASSERT_EQ("/foo/bar/v2?appkey=zzzzzz", std::string(path));

  strncpy(path, "/foo/", sizeof(path));
  rc = _rtm_test_prepare_path(rtm, path, "zzzzzz");
  ASSERT_EQ(RTM_OK, rc);
  ASSERT_EQ("/foo/v2?appkey=zzzzzz", std::string(path));

  strncpy(path, "/foo", sizeof(path));
  rc = _rtm_test_prepare_path(rtm, path, "zzzzzz");
  ASSERT_EQ(RTM_OK, rc);
  ASSERT_EQ("/foo/v2?appkey=zzzzzz", std::string(path));
}

class RTMEnvironment: public ::testing::Environment {
  public:
    void TearDown() override {
      std::queue<event_t> event_queue_empty;
      std::swap(event_queue, event_queue_empty);

      std::queue<std::string> message_queue_empty;
      std::swap(message_queue, message_queue_empty);
    }
};

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::AddGlobalTestEnvironment(new RTMEnvironment());
    load_credentials();

#ifdef _WIN32
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD(2, 2);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        std::cerr << "WSAStartup failed with " << err << std::endl;
    }
#endif

  int64_t seed = std::chrono::system_clock::now().time_since_epoch() / std::chrono::milliseconds(1);
  srand(seed);

  return RUN_ALL_TESTS();
}

TEST(rtm_test, wait_ping) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  ASSERT_EQ(rtm_get_ws_ping_interval(rtm), 45);
  rtm_set_ws_ping_interval(rtm, 1);
  ASSERT_EQ(rtm_get_ws_ping_interval(rtm), 1);

  time_t last_ping_ts = rtm->last_ping_ts;
  rtm_wait_timeout(rtm, 3);
  ASSERT_GT(rtm->last_ping_ts, last_ping_ts);
}

TEST(rtm_test, publish_noack_ping) {
  void *memory = alloca(rtm_client_size);
  rtm_client_t *rtm = rtm_init(memory, pdu_recorder, nullptr);
  int rc = rtm_connect(rtm, endpoint, appkey);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  rtm_set_ws_ping_interval(rtm, 2);

  time_t last_ping_ts = rtm->last_ping_ts;
  std::string const channel = make_channel();

  time_t start = time(NULL);
  while (TRUE) {
    time_t now = time(NULL);
    if (now - start > 3) {
      break;
    }
    rc = rtm_publish_string(rtm, channel.c_str(), "my message", nullptr);
    ASSERT_EQ(RTM_OK, rc)<< "Failed while publish to channel";
  };

  ASSERT_GT(rtm->last_ping_ts, last_ping_ts);
}
