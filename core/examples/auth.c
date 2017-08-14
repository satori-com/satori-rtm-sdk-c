#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <rtm.h>

#define NONCE_SIZE 32

// Replace these values with your project's credentials
// from DevPortal (https://developer.satori.com/)
static char const *endpoint = YOUR_ENDPOINT;
static char const *appkey = YOUR_APPKEY;
static char const *role = YOUR_ROLE;
static char const *role_secret = YOUR_ROLE_SECRET;

typedef struct {
    int authenticated;
    char nonce[NONCE_SIZE];
} client_state;

void pdu_handler(rtm_client_t *client, const rtm_pdu_t *pdu) {
  client_state *state = (client_state *) rtm_get_user_context(client);
  switch (pdu->action) {
    case RTM_ACTION_HANDSHAKE_OK:
      strncpy(state->nonce, pdu->nonce, NONCE_SIZE);
      state->nonce[NONCE_SIZE - 1] = 0;
      break;
    case RTM_ACTION_AUTHENTICATE_OK:
      state->authenticated = 1;
      break;
    case RTM_ACTION_HANDSHAKE_ERROR:
    case RTM_ACTION_AUTHENTICATE_ERROR:
      fprintf(stderr, "Failed to authenticate %s: %s\n", pdu->error, pdu->reason);
      break;
    default:
      rtm_default_pdu_handler(client, pdu);
      break;
  }
}

int authenticate(rtm_client_t *client) {
  unsigned request_id;
  rtm_status rc = rtm_handshake(client, role, &request_id);
  client_state *state = (client_state *) rtm_get_user_context(client);

  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to send handshake request: %s\n", rtm_error_string(rc));
    return rc;
  }

  rc = rtm_wait_timeout(client, 10 /* seconds */);
  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to receive handshake reply: %s\n", rtm_error_string(rc));
    return rc;
  }

  rc = rtm_authenticate(client, role_secret, state->nonce, &request_id);
  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to send authenticate request: %s\n", rtm_error_string(rc));
    return rc;
  }

  rc = rtm_wait_timeout(client, 10 /* seconds */);
  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to receive authenticate reply: %s\n", rtm_error_string(rc));
    return rc;
  }

  if (!state->authenticated) {
    return RTM_ERR_PARAM;
  }

  return RTM_OK;
}

int main(int argc, const char *argv[]) {
  void *memory = malloc(rtm_client_size);
  client_state state = {0};
  rtm_client_t *client = rtm_init(memory, &pdu_handler, &state);
  rtm_status rc = rtm_connect(client, endpoint, appkey);

  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to connect to RTM: %s\n", rtm_error_string(rc));
    goto cleanup;
  }

  printf("Connected to Satori RTM and authenticated as %s.\n", role);

  rc = authenticate(client);
  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to authenticate: %s\n", rtm_error_string(rc));
    goto cleanup;
  }

  cleanup:
  rtm_close(client);
  free(client);
  return rc;
}
