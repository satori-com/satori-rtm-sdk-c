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

struct pdu_t {
  std::string action;
  std::string body;
  unsigned request_id = 0;
};

std::queue<pdu_t> pdu_queue;
std::queue<std::string> message_queue;

void pdu_recorder(rtm_client_t *rtm, const rtm_pdu_t *pdu){
  // add pdu
  pdu_t pdu_copy;
  pdu_copy.request_id = pdu->request_id;
  pdu_copy.action = std::string(pdu->action);
  pdu_copy.body = std::string(pdu->body ? pdu->body : "");
  pdu_queue.push(pdu_copy);

  // add channel data
  size_t const size = 1024;
  auto buf = std::vector<char>(size);
  rtm_parse_subscription_data(rtm, pdu, &buf[0], size,
      [](rtm_client_t *rtm, const char *channel, const char *message) {
        message_queue.push(std::string(message));
      });
}

int next_pdu(rtm_client_t *rtm, pdu_t* pdu) {
  int rc = RTM_OK;
  while (pdu_queue.size() == 0 && rc == RTM_OK) {
    rc = rtm_wait_timeout(rtm, 15);
  }
  if (pdu_queue.size() != 0) {
    *pdu = pdu_queue.front();
    pdu_queue.pop();
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
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  int rc = rtm_connect(rtm, endpoint, appkey, rtm_default_pdu_handler, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  std::string const channel = make_channel();
  rc = rtm_subscribe(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while subscribe to channel";
  rtm_close(rtm);
}

TEST(rtm_test, publish_and_subscribe_with_history) {
  unsigned int request_id;
  pdu_t pdu;
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  int rc = rtm_connect(rtm, endpoint, appkey, &pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();
  rc = rtm_publish_string(rtm, channel.c_str(), "my message", &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publishing";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ("rtm/publish/ok", pdu.action);

  std::string const body = R"({"channel":")" + channel + R"(","history":{"count":1}})";
  rc = rtm_subscribe_with_body(rtm, body.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while subscribing";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ("rtm/subscribe/ok", pdu.action);

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ("rtm/subscription/data", pdu.action);

  ASSERT_EQ(R"("my message")", message_queue.front());
  message_queue.pop();

  rtm_close(rtm);
}

TEST(rtm_test, connect_ssl) {
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  int rc = rtm_connect(rtm, endpoint, appkey, &pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  rtm_close(rtm);
}

TEST(rtm_test, publish) {
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));

  int rc = rtm_connect(rtm, endpoint, appkey, &pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  std::string const channel = make_channel();
  rc = rtm_publish_string(rtm, channel.c_str(), "my message", nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publish to channel";

  rtm_close(rtm);
}

TEST(rtm_test, overflow) {
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));

  int rc = rtm_connect(rtm, endpoint, appkey, &pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  std::string const channel = make_channel();

  std::string big_body(16 * 1024 * 1024, 'a');
  rc = rtm_subscribe_with_body(rtm, big_body.c_str(), nullptr);
  ASSERT_EQ(RTM_ERR_WRITE, rc)<< "Expected rtm_subscribe_with_body to fail";

  rtm_close(rtm);
}

TEST(rtm_test, publish_json_and_read) {
  unsigned int request_id;
  pdu_t pdu;
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));

  int rc = rtm_connect(rtm, endpoint, appkey, &pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();
  const std::string msg = R"({"foo":"bar"})";
  rc = rtm_publish_json(rtm, channel.c_str(), msg.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publish to channel";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ("rtm/publish/ok", pdu.action);

  rc = rtm_read(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publish to channel";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ("rtm/read/ok", pdu.action);
  ASSERT_EQ(json({{"foo", "bar"}}), json::parse(pdu.body)["message"]);

  rtm_close(rtm);
}

TEST(rtm_test, read_write_delete) {
  unsigned int request_id;
  pdu_t pdu;
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));

  int rc = rtm_connect(rtm, endpoint, appkey, &pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();

  rc = rtm_read(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publish to channel";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ("rtm/read/ok", pdu.action);
  ASSERT_EQ(request_id, pdu.request_id);
  ASSERT_TRUE(json::parse(pdu.body)["message"].is_null());

  rc = rtm_write_string(rtm, channel.c_str(), "msg", &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while write";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ("rtm/write/ok", pdu.action);

  rc = rtm_read(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while read";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ("rtm/read/ok", pdu.action);
  ASSERT_EQ(request_id, pdu.request_id);
  ASSERT_EQ("msg", json::parse(pdu.body)["message"].get<std::string>());

  rc = rtm_delete(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while delete";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ("rtm/delete/ok", pdu.action);

  rc = rtm_read(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while read";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while wait PDU";
  ASSERT_EQ("rtm/read/ok", pdu.action);
  ASSERT_EQ(request_id, pdu.request_id);
  ASSERT_TRUE(json::parse(pdu.body)["message"].is_null());

  rtm_close(rtm);
}

TEST(rtm_test, handshake_and_authenticate) {
  unsigned int request_id;
  pdu_t pdu;
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  int rc = rtm_connect(rtm, endpoint, appkey, pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  rc = rtm_handshake(rtm, role_name, &request_id);
  ASSERT_EQ(rc, RTM_OK) << "Failed to send rtm/handshake";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ("auth/handshake/ok", pdu.action);

  std::string nonce = json::parse(pdu.body)["data"]["nonce"];

  rc = rtm_authenticate(rtm, role_secret, nonce.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to send auth/authenticate";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ("auth/authenticate/ok", pdu.action);

  rtm_close(rtm);
}

TEST(rtm_test, publish_and_receive) {
  unsigned int request_id;
  pdu_t pdu;
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  int rc = rtm_connect(rtm, endpoint, appkey, pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();
  rc = rtm_subscribe(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(rc, RTM_OK) << "Failed to subscribe";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ("rtm/subscribe/ok", pdu.action);

  rc = rtm_publish_string(rtm, channel.c_str(), "my message", nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while publishing";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ("rtm/subscription/data", pdu.action);

  ASSERT_EQ(R"("my message")", message_queue.front());
  message_queue.pop();

  rtm_close(rtm);
}

TEST(rtm_test, publish_ws_frame_with_126_bytes_payload) {
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  int rc = rtm_connect(rtm, endpoint, appkey, pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  // channel is hardcoded with fixed length to get 126 bytes payload for WS frame
  unsigned int request_id;
  rc = rtm_publish_json(rtm, "xxxxxxxxxxxxxxx", "{\n   \"cmd_data\" : \"1\",\n   \"cmd_type\" : \"ack\"\n}\n", &request_id);
  ASSERT_EQ(RTM_OK, rc) << "Failed while publishing";

  pdu_t pdu;
  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait publish response";
  ASSERT_EQ("rtm/publish/ok", pdu.action);

  rtm_close(rtm);
}

TEST(rtm_test, disconnect) {
  unsigned int request_id;
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  int rc = rtm_connect(rtm, endpoint, appkey, &pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  rtm_close(rtm);
  std::string const channel = make_channel();
  rc = rtm_subscribe(rtm, channel.c_str(), &request_id);
  ASSERT_GT(RTM_OK, rc)<< "Susbcription succeeded, but RTM should have been closed";
}

TEST(rtm_test, rtm_poll_does_not_hang_ssl) {
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  int rc = rtm_connect(rtm, endpoint, appkey, &pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  ASSERT_EQ(RTM_WOULD_BLOCK, rtm_poll(rtm)) << "Failed to poll";

  rtm_close(rtm);
}


TEST(rtm_test, rtm_poll_does_not_hang_nossl) {
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  int rc = rtm_connect(rtm, endpoint, appkey, &pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  ASSERT_EQ(RTM_WOULD_BLOCK, rtm_poll(rtm)) << "Failed to poll";

  rtm_close(rtm);
}

TEST(rtm_test, rtm_wait_timeout) {
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  int rc = rtm_connect(rtm, endpoint, appkey, &pdu_recorder, nullptr);
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
  ASSERT_EQ(rtm->is_verbose, NO) << "verbose_logging Unable to disable verbose loggin";

  rtm_enable_verbose_logging(rtm);
  ASSERT_EQ(rtm->is_verbose, YES) << "verbose_logging Unable to enable verbose loggin";
}

TEST(rtm_test, log_message) {
  const char *str = "Test log";

  rtm_status status = _rtm_log_message(RTM_OK, str);
  ASSERT_EQ(status, RTM_OK);
}

TEST(rtm_test, unsubscribe) {
  unsigned int request_id;
  pdu_t pdu;

  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  int rc = rtm_connect(rtm, endpoint, appkey, &pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";
  std::string const channel = make_channel();
  rc = rtm_subscribe(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while subscribing to channel";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait subscribe response";
  ASSERT_EQ("rtm/subscribe/ok", pdu.action);

  rc = rtm_unsubscribe(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while unsubscribing from channel";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait unsibscribe response";
  ASSERT_EQ("rtm/unsubscribe/ok", pdu.action);

  rtm_close(rtm);
}

TEST(rtm_test, check_rtm_fd) {
  int fd;
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  int rc = rtm_connect(rtm, endpoint, appkey, rtm_default_pdu_handler, nullptr);
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

  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  int rc = rtm_connect(rtm, endpoint, appkey, &pdu_recorder, &context);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  u_context *rtm_context = static_cast<u_context *>(rtm_get_user_context(rtm));
  ASSERT_EQ(context.user_id, rtm_context->user_id);
  ASSERT_EQ(context.data, rtm_context->data);

  rtm_close(rtm);
}

TEST(rtm_test, rtm_default_pdu_handler) {
  char *c_stdout;
  unsigned int request_id;
  std::string const channel = make_channel();
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));

  int rc = rtm_connect(rtm, endpoint, appkey, rtm_default_pdu_handler, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  rc = rtm_write_string(rtm, channel.c_str(), "publish_msg", &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while write";
  
  rc = rtm_wait_timeout(rtm, 15);
  ASSERT_EQ(RTM_OK, rc)<< "Failed while waiting rtm response";
  rtm_close(rtm);
}

TEST(rtm_test, read_with_body) {
  unsigned int request_id;
  pdu_t pdu;
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));

  std::string const channel = make_channel();

  int rc = rtm_connect(rtm, endpoint, appkey, &pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const body = R"({"channel":")" + channel + R"("})";

  // Read from the non-existing channel
  rc = rtm_read_with_body(rtm, body.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to read with body";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(RTM_OK, rc) << "Failed to get next PDU";
  ASSERT_EQ("rtm/read/ok", pdu.action);
  ASSERT_TRUE(json::parse(pdu.body)["message"].is_null());

  // Publish 3 messages
  for (int i = 0; i < 3; i++) {
    char str[2];
    sprintf(str, "%d", i);
    rc = rtm_publish_string(rtm, channel.c_str(), str, &request_id);
    ASSERT_EQ(RTM_OK, rc)<< "Failed while write";
    rc = next_pdu(rtm, &pdu);
    ASSERT_EQ(RTM_OK, rc) << "Failed to get next PDU";
    ASSERT_EQ("rtm/publish/ok", pdu.action);
  }

  rc = rtm_read_with_body(rtm, body.c_str(), &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to read with body";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(RTM_OK, rc) << "Failed to get next PDU";
  ASSERT_EQ("rtm/read/ok", pdu.action);
  ASSERT_EQ("2", json::parse(pdu.body)["message"].get<std::string>());

  rtm_close(rtm);
}

TEST(rtm_test, rtm_write_json) {
  json test_json;
  unsigned int request_id;
  pdu_t pdu;
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  std::string const channel = make_channel();

  int rc = rtm_connect(rtm, endpoint, appkey, &pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  test_json["intval"] = 12345;
  test_json["bool"] = true;
  test_json["list"] = {1, 2, 3};
  test_json["object"] = {{"currency", "USD"}, {"value", 42.99}};

  rtm_write_json(rtm, channel.c_str(), test_json.dump().c_str(), &request_id);
  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(RTM_OK, rc) << "Failed to get next PDU";
  ASSERT_EQ("rtm/write/ok", pdu.action);

  rtm_read(rtm, channel.c_str(), &request_id);
  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(RTM_OK, rc) << "Failed to get next PDU";
  ASSERT_EQ("rtm/read/ok", pdu.action);
  ASSERT_EQ(test_json, json::parse(pdu.body)["message"]);

  rtm_close(rtm);
}

TEST(rtm_test, publish_and_receive_all_json_types) {
  unsigned int request_id;
  pdu_t pdu;
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  int rc = rtm_connect(rtm, endpoint, appkey, pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();
  rc = rtm_subscribe(rtm, channel.c_str(), &request_id);

  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
  ASSERT_EQ("rtm/subscribe/ok", pdu.action);

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

      rc = next_pdu(rtm, &pdu);
      ASSERT_EQ(rc, RTM_OK) << "Failed to wait";
      ASSERT_EQ("rtm/subscription/data", pdu.action);

      ASSERT_EQ(message, message_queue.front());
      message_queue.pop();
  }

  rtm_close(rtm);
}

TEST(rtm_test, DISABLED_rtm_search_test) {
  unsigned int request_id;
  pdu_t pdu;
  auto rtm = static_cast<rtm_client_t *>(alloca(rtm_client_size));
  int rc = rtm_connect(rtm, endpoint, appkey, pdu_recorder, nullptr);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to create RTM connection";

  std::string const channel = make_channel();
  rc = rtm_publish_string(rtm, channel.c_str(), "test", &request_id);
  ASSERT_EQ(RTM_OK, rc)<< "Failed to send a publish request";

  rc = next_pdu(rtm, &pdu);
  ASSERT_EQ(rc, RTM_OK) << "Failed to receive an ack";
  ASSERT_EQ("rtm/publish/ok", pdu.action);

  rc = rtm_search(rtm, channel.c_str(), &request_id);
  ASSERT_EQ(rc, RTM_OK) << "Failed to send a search request";

  std::vector<std::string> channels;

  while (true) {
    rc = next_pdu(rtm, &pdu);
    ASSERT_EQ(rc, RTM_OK) << "Failed to receive pdu";

    auto body = json::parse(pdu.body);

    std::vector<std::string> new_channels = body["channels"];
    channels.insert(channels.end(), new_channels.begin(), new_channels.end());

    bool is_final = pdu.action == "rtm/search/ok";

    if (is_final) {
      break;
    }
  }

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
  rc = _rtm_test_parse_endpoint(rtm, "wss://example.com/", hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("443", std::string(port));
  ASSERT_EQ("/", std::string(path));
  ASSERT_EQ(1, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(rtm, "ws://example.com/", hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("80", std::string(port));
  ASSERT_EQ("/", std::string(path));
  ASSERT_EQ(0, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(rtm, "ws://example.com", hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("80", std::string(port));
  ASSERT_EQ("/", std::string(path));
  ASSERT_EQ(0, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(rtm, "ws://example.com/v3", hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("80", std::string(port));
  ASSERT_EQ("/v3", std::string(path));
  ASSERT_EQ(0, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(rtm, "ws://example.com:8080/v3", hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("8080", std::string(port));
  ASSERT_EQ("/v3", std::string(path));
  ASSERT_EQ(0, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(rtm, "wss://example.com:8080/foo/bar/", hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("8080", std::string(port));
  ASSERT_EQ("/foo/bar/", std::string(path));
  ASSERT_EQ(1, use_tls);
  ASSERT_EQ(RTM_OK, rc);

  memset(hostname, 0, sizeof(hostname));
  memset(port, 0, sizeof(port));
  memset(path, 0, sizeof(path));
  rc = _rtm_test_parse_endpoint(rtm, "wss://example.com:8080/foo/bar", hostname, port, path, &use_tls);
  ASSERT_EQ("example.com", std::string(hostname));
  ASSERT_EQ("8080", std::string(port));
  ASSERT_EQ("/foo/bar", std::string(path));
  ASSERT_EQ(1, use_tls);
  ASSERT_EQ(RTM_OK, rc);
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
      std::queue<pdu_t> pdu_queue_empty;
      std::swap(pdu_queue, pdu_queue_empty);

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
