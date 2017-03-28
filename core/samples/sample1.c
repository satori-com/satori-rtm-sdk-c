#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <Windows.h>
static void sleep(int seconds) {
    return Sleep(seconds);
}
#else
#include <unistd.h>
#endif

#include <rtm.h>

static char const *endpoint = "wss://myapp.api.satori.com/";
static char const *appkey = "my_appkey";
static char const *channel = "my_channel";

static char const *role = "my_role";
static char const *role_secret = "my_secret";

static char *last_nonce = NULL;
static int authenticated = 0;

void my_pdu_handler(rtm_client_t *rtm, const rtm_pdu_t *pdu) {
  switch (pdu->outcome) {
    case RTM_OUTCOME_HANDSHAKE_OK:
      printf("Copying nonce %s\n", pdu->nonce);
      last_nonce = (char *)malloc(strlen(pdu->nonce) + 1);
      strcpy(last_nonce, pdu->nonce);
      break;
    case RTM_OUTCOME_AUTHENTICATE_OK:
      authenticated = 1;
      break;
    case RTM_OUTCOME_AUTHENTICATE_ERROR:
      fprintf(stderr, "Authentication error: %s\n", pdu->error);
      fprintf(stderr, "Authentication error reason: %s\n", pdu->reason);
      break;
    case RTM_OUTCOME_SUBSCRIPTION_DATA: {
      printf("Subscription data\n");
      char *message;
      while ((message = rtm_iterate(&pdu->message_iterator))) {
          printf("New message: %s\n", message);
      }
      break;
    }
    default:
      break;
  }
}

int authenticate(rtm_client_t *rtm) {
  unsigned request_id;
  rtm_status rc = rtm_handshake(rtm, role, &request_id);
  if (rc) {
    fprintf(stderr, "Failed to send handshake request\n");
    return rc;
  }

  rc = rtm_wait_timeout(rtm, 10 /* seconds */);
  if (rc) {
    fprintf(stderr, "Failed to receive handshake reply\n");
    return rc;
  }

  if (!last_nonce) {
    fprintf(stderr, "Failed to get nonce from the handshake reply\n");
    return RTM_ERR_PARAM;
  }

  rc = rtm_authenticate(rtm, role_secret, last_nonce, &request_id);
  if (rc) {
    fprintf(stderr, "Failed to send authenticate request\n");
    return rc;
  }

  rc = rtm_wait_timeout(rtm, 10 /* seconds */);
  if (rc) {
    fprintf(stderr, "Failed to receive authenticate reply\n");
    return rc;
  }

  if (!authenticated) {
    fprintf(stderr, "Authentication failed\n");
    return RTM_ERR_PARAM;
  }

  return RTM_OK;
}

int main(int argc, const char *argv[]) {
  rtm_client_t *rtm = (rtm_client_t *)malloc(rtm_client_size);
  unsigned request_id;
  rtm_status rc;

  rc = rtm_connect(rtm, endpoint, appkey, &my_pdu_handler, NULL);

  if (rc) {
    fprintf(stderr, "Unable to connect to RTM: %s\n", rtm_error_string(rc));
    free(rtm);
    return rc;
  }

  fprintf(stderr, "Connected to RTM\n");

  rc = authenticate(rtm);
  if (rc) {
      rtm_close(rtm);
      free(rtm);
      return rc;
  }

  fprintf(stderr, "Authenticated as %s\n", role);

  rc = rtm_subscribe(rtm, channel, &request_id);
  if (rc) {
    fprintf(stderr, "Unable to subscribe to channel: %s\n", rtm_error_string(rc));
    rtm_close(rtm);
    free(rtm);
    return rc;
  }
  rtm_publish_string(rtm, channel, "Hello world!", NULL);
  for (int i = 0; i < 100; i++) {
    char buffer[1024];
    sprintf(buffer, "This is the index %d", i);
    rtm_publish_string(rtm, channel, buffer, NULL);
  }

  fprintf(stderr, "Subscribed\n");
  sleep(1);

  time_t start_time = time(NULL);
  while (1) {
    rc = rtm_wait_timeout(rtm, 10);
    if (rc != RTM_OK)
      break;
    // loop for a total of 10s.
    if (time(NULL) - start_time > 10)
      break;
  }

  rtm_close(rtm);

  fprintf(stderr, "Done\n");

  free(rtm);
  return rc;
}