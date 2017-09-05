/*
  This is the source code for our weather station tutorial. See satori.com for
  the circuit for this sketch.
*/

#include <DHT.h>
#include <DHT_U.h>
#include <ESP8266WiFi.h>
#include <rtm.h>

// Configuration for RTM. Register at https://developer.satori.com/
// to obtain these values, then enter them here.
static char const *endpoint = YOUR_ENDPOINT;
static char const *appkey = YOUR_APPKEY;

// Credentials for your WiFi
static char const *ssid = YOUR_SSID;
static char const *psk = YOUR_PSK;

// Reserve 1kB of memory for RTM's buffers
alignas(rtm_client_t) char *rtm_mem[RTM_CLIENT_SIZE_WITH_BUFFERS(1000)];
rtm_client_t *rtm_client;

// These variables track the program's state
unsigned request_id;
bool connected;
unsigned long time_since_publish_ok;
unsigned long update_time;

// If you used different pins than in the drawing, set them here:
const int DHT_pin = D4;
const int LED_pin = D5;

// Initialize the Adafruit DHT library to read data from the
// humidity/temperature sensor.
// If you used a DHT11, replace DHT22 with DHT11!
DHT dht(DHT_pin, DHT22);

void pdu_handler(rtm_client_t *rtm_client, const rtm_pdu_t *pdu);


void setup() {
  // Initialize serial console for debugging
  Serial.begin(9600);
  Serial.println("Starting");
  // Connect to WiFi
  WiFi.mode(WIFI_STA);
  do {
    WiFi.begin(ssid, psk);
  } while (WiFi.waitForConnectResult() != WL_CONNECTED);
  Serial.println("Connected to the WiFi");

  // Initialize the LED pin for output
  pinMode(LED_pin, OUTPUT);

  // Fire up the RTM SDK:
  // Prepare the client structure and tell RTM that we will process PDUs in
  // pdu_handler
  rtm_client = rtm_init_ex(rtm_mem, sizeof(rtm_mem), pdu_handler, nullptr);
  // Tell RTM that we do not want to allocate any additional memory, but to
  // handle out-of-memory situations gracefully
  rtm_set_allocator(rtm_client, rtm_null_malloc, rtm_null_free);
  // Establish a connection to RTM. We do not need to check for errors here as
  // the loop() function will reboot if the connection is gone.
  rtm_status rc = rtm_connect(rtm_client, endpoint, appkey);
  if (RTM_OK != rc) {
    Serial.println("Failed to connect to Satori");
    delay(5000);
    ESP.restart();
  }
  // Subscribe to the "esp" channel to receive messages that activate
  // the LED
  rc =  rtm_subscribe(rtm_client, "esp", &request_id);
  if (RTM_OK != rc) {
    Serial.println("Failed to subscribe to esp channel");
    delay(5000);
    ESP.restart();
  }
  // Initialize the reboot counter (see below)
  time_since_publish_ok = millis();

  Serial.println("Connected to Satori");
  // Enable the ESP’s watchdog: If processing hangs for 4s, the watchdog
  // automatically reboots the ESP.
  ESP.wdtEnable(WDTO_4S);
}

void loop() {
  if (millis() - update_time > 2000) {
    // If it has been 2s since our last measurement, perform a new one.
    float h = dht.readHumidity();
    float t = dht.readTemperature(true); // Return temperature in °F

    Serial.print("Humidity = ");
    Serial.print(h);
    Serial.print(", Temperature = ");
    Serial.println(t);

    // Do a sanity check: Realistic temperatures (in °F) are between
    // 0°F and 170°F all the time.
    if (t >= 0 && t < 170) {
      // If we have not received an acknowledgement for a published message for
      // 60s straight, reboot.
      if (millis() - time_since_publish_ok > 60000) {
        Serial.println("Acknowledgement for last publish is not received");
        ESP.restart();
      }

      // Prepare a JSON message with both measurements. Arduino's sprintf()
      // does not support %f, so instead we convert the values to integers.
      char msg[256];
      sprintf(msg, "{\"temperature\": %d.%02d, \"humidity\": %d.%02d}",
              (int)t, ((int)(t * 100)) % 100, (int)h, ((int)(h * 100)) % 100);

      Serial.print("Publishing a message to Satori: ");
      Serial.println(msg);

      // Publish the message to the esp channel and request an acknowledgement
      // by supplying the request_id parameter
      rtm_status rc = rtm_publish_json(rtm_client, "esp", msg, &request_id);
      if (RTM_OK != rc) {
        Serial.println("Failed to publish a message");
        delay(5000);
        ESP.restart();
      }

      Serial.println("Message sent.");
    }
    update_time = millis();
  }

  rtm_poll(rtm_client);

  // Wait 0.01s, then loop
  delay(10);

  // Feed the watchdog timer
  ESP.wdtFeed();
}

void pdu_handler(rtm_client_t *rtm_client, const rtm_pdu_t *pdu) {
  // This function is called whenever a PDU is received. Only two
  // two types of PDUs are important:
  // RTM_ACTION_SUBSCRIPTION_DATA, which contains a new channel message
  // RTM_ACTION_PUBLISH_OK, which is called by Satori to acknowledge that
  // it received one of our messages
  if (pdu->action == RTM_ACTION_SUBSCRIPTION_DATA) {
    // New channel messages arrived from the "esp" channel. For each of
    // them..
    char *message;
    while ((message = rtm_iterate(&pdu->message_iterator))) {
      // ..check if they contain an "led_on" or “led_off” entry.
      if (strstr(message, "\"led_on\"")) {
        // Turn the LED on
        digitalWrite(LED_pin, HIGH);
      }
      if (strstr(message, "\"led_off\"")) {
        // Turn the LED on
        digitalWrite(LED_pin, LOW);
      }

      // Also print the message for debugging
      Serial.print("Received message: ");
      Serial.println(message);
    }
  } else if (pdu->action == RTM_ACTION_PUBLISH_OK) {
    // Reset the restart timer
    time_since_publish_ok = millis();
  }
}
