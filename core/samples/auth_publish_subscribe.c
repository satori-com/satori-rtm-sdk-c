#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <rtm.h>

#define NONCE_SIZE 32

static char const *endpoint = "wss://myapp.api.satori.com/";
static char const *appkey = "my_appkey";
static char const *role = "my_role";
static char const *role_secret = "my_secret";

static char const *channel = "my_channel";

typedef struct {
  int authenticated;
  char nonce[NONCE_SIZE];
} client_state;

void my_pdu_handler(rtm_client_t *rtm, const rtm_pdu_t *pdu) {
  client_state *state = (client_state *) rtm_get_user_context(rtm);
  switch (pdu->action) {
    case RTM_ACTION_HANDSHAKE_OK:
      strncpy(state->nonce, pdu->nonce, NONCE_SIZE - 1);
      break;
    case RTM_ACTION_AUTHENTICATE_OK:
      fprintf(stderr, "Authentication succeed\n");
      state->authenticated = 1;
      break;
    case RTM_ACTION_GENERAL_ERROR:
    case RTM_ACTION_PUBLISH_ERROR:
    case RTM_ACTION_HANDSHAKE_ERROR:
    case RTM_ACTION_SUBSCRIPTION_ERROR:
    case RTM_ACTION_SUBSCRIBE_ERROR:
    case RTM_ACTION_AUTHENTICATE_ERROR:
      fprintf(stderr, " Error: %s - %s\n", pdu->error, pdu->reason);
      break;
    case RTM_ACTION_SUBSCRIPTION_DATA: {
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
  client_state *state = (client_state *) rtm_get_user_context(rtm);

  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to send handshake request\n");
    return rc;
  }

  rc = rtm_wait_timeout(rtm, 10 /* seconds */);
  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to receive handshake reply\n");
    return rc;
  }

  rc = rtm_authenticate(rtm, role_secret, state->nonce, &request_id);
  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to send authenticate request\n");
    return rc;
  }

  rc = rtm_wait_timeout(rtm, 10 /* seconds */);
  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to receive authenticate reply\n");
    return rc;
  }

  if (!state->authenticated) {
    fprintf(stderr, "Authentication failed\n");
    return RTM_ERR_PARAM;
  }

  return RTM_OK;
}

int main(int argc, const char *argv[]) {
  rtm_client_t *rtm = (rtm_client_t *)malloc(rtm_client_size);
  client_state state = {0};
  rtm_init(rtm, &my_pdu_handler, &state);
  rtm_status rc;

  rc = rtm_connect(rtm, endpoint, appkey);

  if (RTM_OK != rc) {
    fprintf(stderr, "Unable to connect to RTM: %s\n", rtm_error_string(rc));
    goto cleanup;
  }

  fprintf(stderr, "Connected to RTM\n");

  rc = authenticate(rtm);
  if (RTM_OK != rc) {
    goto cleanup;
  }

  fprintf(stderr, "Authenticated as %s\n", role);

  unsigned request_id;
  rc = rtm_subscribe(rtm, channel, &request_id);
  if (RTM_OK != rc) {
    fprintf(stderr, "Unable to subscribe to channel: %s\n", rtm_error_string(rc));
    goto cleanup;
  }

  rtm_publish_string(rtm, channel, "Hello world!", NULL);
  for (int i = 0; i < 100; i++) {
    char buffer[1024];
    sprintf(buffer, "This is the index %d", i);
    rtm_publish_string(rtm, channel, buffer, NULL);
  }

  fprintf(stderr, "Subscribed\n");

  time_t start_time = time(NULL);
  while (1) {
    rc = rtm_wait_timeout(rtm, 10);
    if (RTM_OK != rc)
      break;
    // loop for a total of 10s.
    if (time(NULL) - start_time > 10)
      break;
  }


  fprintf(stderr, "Done\n");
  goto cleanup;

  cleanup:
    rtm_close(rtm);
    free(rtm);
    return rc;
}
