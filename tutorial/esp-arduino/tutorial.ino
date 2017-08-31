#include <rtm.h>
#include <ESP8266WiFi.h>
#include <cstdio>

// Replace these values with your project's credentials
// from DevPortal (https://developer.satori.com/)
static char const *endpoint = YOUR_ENDPOINT;
static char const *appkey = YOUR_APPKEY;
static char const *role = YOUR_ROLE;
static char const *role_secret = YOUR_ROLE_SECRET;

// Replace these values with credentials to your access point
static char const *ssid = YOUR_SSID;
static char const *psk = YOUR_PSK;

// RTM leaves it to you how much memory to allocate. There is a minimum (see
// RTM_CLIENT_SIZE), but 1 KiB works. The more you allocate, the more data
// the SDK can buffer and the more data you can send in one burst. But all
// memory you allocate to RTM is lost to other parts of your sketch.
char *client_mem[1000];
rtm_client_t *rtm_client;

// Tutorial state, see below
bool initialization_complete;
int msg_counter;

// Will handle incoming messages
void pdu_handler(rtm_client_t *client, const rtm_pdu_t *pdu);

void setup() {
  Serial.begin(9600);

  // Set up the ESP8266's watch dog timer to be on the safe side in case anything breaks
  // We will publish a message every second and reset the wdt when we receive an
  // acknowledgement for the request.
  ESP.wdtEnable(WDTO_8S);

  // Connect to wifi
  Serial.println("Booting");
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, psk);
  while(WiFi.waitForConnectResult() != WL_CONNECTED){
    WiFi.begin(ssid, psk);
    Serial.println("Retrying..");
  }
  Serial.println("Connected to wifi");

  // Start up RTM client
  rtm_client = rtm_init_ex(client_mem, sizeof(client_mem), pdu_handler, nullptr);

  // Tell RTM to ignore situations where it would have to allocate memory
  // You should set this in production, but for your initial sketches, it might
  // be useful to set functions that log to Serial instead.
  rtm_set_allocator(rtm_client, rtm_null_malloc, rtm_null_free);

  // Tell RTM to log to the serial console
  // Note: This function will only be used if you created the Arduino SDK with
  // logging enabled (or enabled it afterwards by editing rtm_config.h).  By
  // default, logging is disabled for embedded platforms as it adds about 4KiB
  // to the binary.
  rtm_set_error_logger(rtm_client, [](const char *message) {
    Serial.print("RTM error: ");
    Serial.println(message);
  });

  // Repeatedly try to connect
  while(true) {
      int rc = rtm_connect(rtm_client, endpoint, appkey);
      if(rc == RTM_OK) break;

      delay(3000);
      ESP.wdtFeed();
      rtm_close(rtm_client);
      rtm_client = rtm_init_ex(client_mem, sizeof(client_mem), nullptr, nullptr);
  }

  unsigned request_id;
  rtm_status rc = rtm_handshake(rtm_client, role, &request_id);
  if(rc != RTM_OK) {
    Serial.print("Handshake with RTM failed with code ");
    Serial.println(rc);
    delay(1000);
    ESP.restart();
  }

  Serial.println("Connected to Satori, awaiting authentication digest..");
}

void loop() {
  if(initialization_complete) {
    // Only execute this once authenticated & the state is known.
    // Then: Count. Sensor data would be more useful, of course ;-)
    char msg[255];
    sprintf(msg, "Message #%d from ESP8266!", ++msg_counter);

    if(rtm_publish_string(rtm_client, "esp", msg, nullptr) != RTM_OK) {
      Serial.println("Publishing failed.");
      ESP.restart();
    }
  }

  // Try to read in every loop iteration
  // This will execute pdu_handler() if any messages could be read.
  rtm_status rc = rtm_poll(rtm_client);
  if(rc != RTM_OK && rc != RTM_WOULD_BLOCK) {
    // We entered an unexpected error state. Restart.
    Serial.print("Unexpected error state ");
    Serial.println(rc);
    ESP.restart();
  }

  delay(1000);
}

void pdu_handler(rtm_client_t *rtm_client, const rtm_pdu_t *pdu) {
   unsigned request_id;
  if(pdu->action == RTM_ACTION_HANDSHAKE_OK) {
    // 1st step is done, a reply to the handshake was received. It contains
    // a nonce we can use to authenticate.
    Serial.println("Received digest token. Authenticating. Waiting for authorization..");
    rtm_authenticate(rtm_client, role_secret, pdu->nonce, &request_id);
  }
  else if(pdu->action == RTM_ACTION_AUTHENTICATE_OK) {
    // Authentication was successful. Request the latest message from the Channel from Satori.
    Serial.println("Received authorization. Reading the latest message..");
    rtm_read(rtm_client, "esp", &request_id);
  }
  else if(pdu->action == RTM_ACTION_READ_OK) {
    // We received the message. So we can start counting.
    if(memcmp(pdu->message, "\"Message #", 10) == 0) {
      msg_counter = atoi(pdu->message + 10);
    }
    else {
      // Either a malformed message was published, or the channel was empty
      // (pdu->message == "null")
      Serial.print("Message received, but failed to parse: ");
      Serial.println(pdu->message);
    }

    Serial.print("Received latest message. Picking up counting at ");
    Serial.println(msg_counter);
    initialization_complete = true;
  }
  else if(pdu->action == RTM_ACTION_PUBLISH_OK) {
    // We successfully published a message. As discussed above, reset the watchdog timer.
    ESP.wdtFeed();
  }
  else {
    Serial.print("Unexpected PDU #");
    Serial.println(pdu->action);
  }
}

