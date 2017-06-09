#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rtm.h>

// Replace these values with your project's credentials
// from DevPortal (https://developer.satori.com/#/projects)
static char const *endpoint = "YOUR_ENDPOINT";
static char const *appkey = "YOUR_APPKEY";
static char const *role = "YOUR_ROLE";
static char const *role_secret = "YOUR_SECRET";

static char const *channel = "animal_sightings";
static char const *message = "{\"who\": \"zebra\", \"where\":[34.134358, -118.321506]}";

#define MAX_NONCE_SIZE 32

// We'll be keeping the entirety of application state in this struct
struct tutorial_state_t {
    int subscribe_ok;
    int publish_ok;
    int got_message;
    char *last_nonce;
    int authenticated;
};

// This is a callback function that is called by the SDK
// on every incoming pdu
void tutorial_pdu_handler(rtm_client_t *rtm, const rtm_pdu_t *pdu) {

  struct tutorial_state_t *tutorial_state = (struct tutorial_state_t *)rtm_get_user_context(rtm);

  switch(pdu->action) {
    case RTM_ACTION_SUBSCRIBE_OK:
      tutorial_state->subscribe_ok = 1;
      return;
    case RTM_ACTION_SUBSCRIBE_ERROR:
      tutorial_state->subscribe_ok = 0;
      return;
    case RTM_ACTION_PUBLISH_OK:
      tutorial_state->publish_ok = 1;
      return;
    case RTM_ACTION_PUBLISH_ERROR:
      tutorial_state->publish_ok = 0;
      return;
    case RTM_ACTION_SUBSCRIPTION_DATA:
      tutorial_state->got_message = 1;
      break;
    case RTM_ACTION_HANDSHAKE_OK:
      tutorial_state->last_nonce = malloc(strlen(pdu->nonce) + 1);
      strcpy(tutorial_state->last_nonce, pdu->nonce);
      break;
    case RTM_ACTION_AUTHENTICATE_OK:
      tutorial_state->authenticated = 1;
      break;
    default:
      break;
  }

  // This implementation of pdu handler is provided by the SDK in rtm.h header.
  // It prints the given pdu to stdout. We use it here to see all the replies
  // and subscription data when running the program.
  rtm_default_pdu_handler(rtm, pdu);
}

int authenticate(rtm_client_t *rtm) {
  unsigned request_id;
  struct tutorial_state_t *tutorial_state = (struct tutorial_state_t *)rtm_get_user_context(rtm);

  rtm_status status = rtm_handshake(rtm, role, &request_id);
  if (status) {
    fprintf(stderr, "Failed to send handshake request\n");
    return status;
  }

  status = rtm_wait_timeout(rtm, 10 /* seconds */);
  if (status) {
    fprintf(stderr, "Failed to receive handshake reply\n");
    return status;
  }

  if (!tutorial_state->last_nonce) {
    fprintf(stderr, "Failed to get nonce from the handshake reply\n");
    return RTM_ERR_PARAM;
  }

  status = rtm_authenticate(rtm, role_secret, tutorial_state->last_nonce, &request_id);
  free(tutorial_state->last_nonce);
  tutorial_state->last_nonce = NULL;

  if (status) {
    fprintf(stderr, "Failed to send authenticate request\n");
    return status;
  }

  status = rtm_wait_timeout(rtm, 10 /* seconds */);
  if (status) {
    fprintf(stderr, "Failed to receive authenticate reply\n");
    return status;
  }

  if (!tutorial_state->authenticated) {
    fprintf(stderr, "Authentication failed\n");
    return RTM_ERR_PARAM;
  }

  return RTM_OK;
}

int main(void) {
  // C SDK does not allocate memory on its own so you’re required to give it a
  // buffer to work with beforehand.
  rtm_client_t *rtm = (rtm_client_t *)malloc(rtm_client_size);

  rtm_status status;
  struct tutorial_state_t tutorial_state = {0};

  // All functions that take 'rtm' as an argument (like rtm_subscribe)
  // must be called only after rtm_init.
  rtm_init(rtm, tutorial_pdu_handler, &tutorial_state);

  status = rtm_connect(rtm, endpoint, appkey);

  if (status != RTM_OK) {
    fprintf(stderr, "Unable to connect to RTM\n");
    free(rtm);
    return status;
  }

  // Perform authentication process to obtain permissions to subscribe
  // and publish to the channel. This step is not necessary if you just
  // want to read from an open data channel.
  status = authenticate(rtm);
  if (status) {
      rtm_close(rtm);
      free(rtm);
      return status;
  }

  fprintf(stderr, "Authenticated as %s\n", role);

  // Send a subscribe request
  unsigned request_id;
  status = rtm_subscribe(rtm, channel, &request_id);
  if (status != RTM_OK) {
    fprintf(stderr, "Unable to send subscribe request\n");
    rtm_close(rtm);
    free(rtm);
    return status;
  }

  // Wait for a subscribe reply
  status = rtm_wait_timeout(rtm, 10 /* seconds */);
  if (status != RTM_OK) {
    if (status == RTM_ERR_TIMEOUT) {
        fprintf(stderr, "Unable to receive subscribe reply in time\n");
    } else {
        fprintf(stderr, "Failed to receive subscribe reply, error %d\n", status);
    }
    rtm_close(rtm);
    free(rtm);
    return status;
  }

  // Note that RTM_OK result above refers only to the fact that we
  // have successfully received a reply. RTM_OK does not mean that the outcome
  // inside that reply was itself an 'ok'. The inspection of the reply happens
  // in tutorial_pdu_handler function and here we the use 'subscribe_ok' variable
  // which was or was not set to 1 in that process.
  if (!tutorial_state.subscribe_ok) {
    fprintf(stderr, "Subscribe reply was an error\n");
    rtm_close(rtm);
    free(rtm);
    return status;
  }

  printf("Successfully subscribed to %s\n", channel);

  // Publish a message, taking care of error handling in similar manner.
  status = rtm_publish_json(rtm, channel, message, &request_id);
  if (status != RTM_OK) {
    fprintf(stderr, "Failed to send publish request\n");
    rtm_close(rtm);
    free(rtm);
    return status;
  }

  // Now we're expecting two PDUs to arrive: a publish reply one and (if publish
  // succeeded) a subscription data one. There is no guarantee of which one comes
  // first.
  // Successful status from call to rtm_wait_timeout means that one or more PDUs
  // were processed. Note that we say "one or more" and it is important because we
  // cannot just call rtm_wait_timeout exactly twice for the two expected
  // messagesWe need to check if we got both PDUs after the first call. And repeat
  // the call if not.
  // Real world applications are more complex than this tutorial and will likely
  // have more convenient abstraction for getting PDUs, but that's out of scope of
  // this tutorial. C Core SDK doesn't provide such built-in abstraction.
  for (int i = 0; i < 2; ++i) {
    status = rtm_wait_timeout(rtm, 10 /* seconds */);
    if (status != RTM_OK) {
      if (status == RTM_ERR_TIMEOUT) {
          fprintf(stderr, "Timeout while waiting for subscription data and publish reply\n");
      } else {
          fprintf(stderr, "Failed to receive publish reply or subscription data, error %d\n", status);
      }
      rtm_close(rtm);
      free(rtm);
      return status;
    }

    if (tutorial_state.publish_ok && tutorial_state.got_message) {
      break;
    }
  }
  if (!tutorial_state.publish_ok) {
    fprintf(stderr, "Publish reply was an error\n");
    rtm_close(rtm);
    free(rtm);
    return status;
  }
  if (!tutorial_state.got_message) {
    fprintf(stderr, "Didn't receive the message\n");
    rtm_close(rtm);
    free(rtm);
    return status;
  }
  printf("Successfully published '%s' to %s\n", message, channel);
  rtm_close(rtm);
  free(rtm);
}