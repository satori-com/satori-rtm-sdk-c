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

static char const *channel = "animals";
static char const *message_as_json = "{\"who\": \"zebra\", \"where\":[34.134358, -118.321506]}";

#define MAX_NONCE_SIZE 32

// We'll be keeping the entirety of application state in this struct
struct tutorial_state_t {
    int subscribe_ok;
    int publish_ok;
    int got_message;
    char last_nonce[MAX_NONCE_SIZE + 1];
    int authenticated;
};

// This is a callback function that is called by the SDK
// on every incoming pdu
void tutorial_pdu_handler(rtm_client_t *rtm, const rtm_pdu_t *pdu) {

  struct tutorial_state_t *tutorial_state = (struct tutorial_state_t *) rtm_get_user_context(rtm);

  switch (pdu->action) {
    case RTM_ACTION_SUBSCRIBE_OK:
      printf("Successfully subscribed to %s\n", pdu->subscription_id);
      tutorial_state->subscribe_ok = 1;
      break;
    case RTM_ACTION_PUBLISH_OK:
      printf("Animal is published\n");
      tutorial_state->publish_ok = 1;
      break;
    case RTM_ACTION_SUBSCRIPTION_DATA: {
      char *message;
      while ((message = rtm_iterate(&pdu->message_iterator))) {
        // Note that unlike other Satori RTM SDKs, C Core SDK does not parse
        // messages into objects, because C has neither appropriate data
        // structures nor JSON parsing functionality in the standard library.
        printf("Animal is received: %s\n", message);
      }
      tutorial_state->got_message = 1;
      break;
    }
    case RTM_ACTION_HANDSHAKE_OK:
      strncpy(tutorial_state->last_nonce, pdu->nonce, MAX_NONCE_SIZE);
      break;
    case RTM_ACTION_AUTHENTICATE_OK:
      tutorial_state->authenticated = 1;
      break;
    case RTM_ACTION_GENERAL_ERROR:
    case RTM_ACTION_AUTHENTICATE_ERROR:
    case RTM_ACTION_HANDSHAKE_ERROR:
    case RTM_ACTION_PUBLISH_ERROR:
    case RTM_ACTION_SUBSCRIBE_ERROR:
    case RTM_ACTION_SUBSCRIPTION_ERROR:
    case RTM_ACTION_SUBSCRIPTION_INFO:
      fprintf(stderr, "error: %s, reason: %s\n", pdu->error, pdu->reason);
      break;
    default:
      rtm_default_pdu_handler(rtm, pdu);
      break;
  }
}

rtm_status handshake_and_authenticate(rtm_client_t *rtm) {
  unsigned request_id;
  struct tutorial_state_t *tutorial_state = (struct tutorial_state_t *) rtm_get_user_context(rtm);

  rtm_status status = rtm_handshake(rtm, role, &request_id);
  if (RTM_OK != status) {
    fprintf(stderr, "Failed to send handshake request: %s\n", rtm_error_string(status));
    return status;
  }

  status = rtm_wait_timeout(rtm, 10 /* seconds */);
  if (RTM_OK != status) {
    fprintf(stderr, "Failed to receive handshake reply: %s\n", rtm_error_string(status));
    return status;
  }

  status = rtm_authenticate(rtm, role_secret, tutorial_state->last_nonce, &request_id);

  if (RTM_OK != status) {
    fprintf(stderr, "Failed to send authenticate request: %s\n", rtm_error_string(status));
    return status;
  }

  status = rtm_wait_timeout(rtm, 10 /* seconds */);
  if (RTM_OK != status) {
    fprintf(stderr, "Failed to receive authenticate reply: %s\n", rtm_error_string(status));
    return status;
  }

  if (!tutorial_state->authenticated) {
    fprintf(stderr, "Authentication failed\n");
    return RTM_ERR_PARAM;
  }

  return RTM_OK;
}

int main(void) {
  struct tutorial_state_t tutorial_state = {0};

  // C SDK does not allocate memory on its own so you're required to give it a
  // buffer to work with beforehand.
  void *memory_for_rtm_client = malloc(rtm_client_size);

  // All functions that take 'rtm' as an argument (like rtm_subscribe)
  // must be called only after rtm_init.
  rtm_client_t *rtm = rtm_init(memory_for_rtm_client, tutorial_pdu_handler, &tutorial_state);

  puts("RTM client config:");
  printf("\tendpoint = %s\n", endpoint);
  printf("\tappkey = %s\n", appkey);
  int should_authenticate = (0 != strcmp(role, "YOUR_ROLE"));
  if (should_authenticate) {
      printf("\tauthenticate? = True (as %s)\n", role);
  } else {
      printf("\tauthenticate? = False\n");
  }

  rtm_status status = rtm_connect(rtm, endpoint, appkey);
  if (RTM_OK != status) {
    fprintf(stderr, "Failed to connect: %s\n", rtm_error_string(status));
    free(rtm);
    return status;
  }
  printf("Connected to Satori!\n");

  if (should_authenticate) {
    // Perform authentication process to obtain permissions to subscribe
    // and publish to the channel. This step is not necessary if you just
    // want to read from an open data channel.
    status = handshake_and_authenticate(rtm);
    if (RTM_OK != status) {
      rtm_close(rtm);
      free(rtm);
      return status;
    }

    printf("Authenticated as %s\n", role);
  }

  // Send a subscribe request
  unsigned request_id;
  status = rtm_subscribe(rtm, channel, &request_id);
  if (RTM_OK != status) {
    fprintf(stderr, "Unable to send subscribe request: %s\n", rtm_error_string(status));
    rtm_close(rtm);
    free(rtm);
    return status;
  }

  // Wait for a subscribe reply
  status = rtm_wait_timeout(rtm, 10 /* seconds */);
  if (status != RTM_OK) {
    fprintf(stderr, "Failed to receive subscribe reply: %s\n", rtm_error_string(status));
    rtm_close(rtm);
    free(rtm);
    return status;
  }

  // Note that RTM_OK result above refers only to the fact that we
  // have successfully received a reply. RTM_OK does not mean that the reply is
  // positive. The inspection of the reply happens in tutorial_pdu_handler
  // function and here we the use 'subscribe_ok' variable
  // which was or was not set to 1 in that process.
  if (!tutorial_state.subscribe_ok) {
    fprintf(stderr, "Subscribe reply was an error\n");
    rtm_close(rtm);
    free(rtm);
    return status;
  }


  while (1) {
    tutorial_state.got_message = 0;
    tutorial_state.publish_ok = 0;

    // Publish a message, taking care of error handling in similar manner.
    status = rtm_publish_json(rtm, channel, message_as_json, &request_id);
    if (status != RTM_OK) {
      fprintf(stderr, "Failed to send publish request: %s\n", rtm_error_string(status));
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
    int i = 0;
    for (i = 0; i < 2; ++i) {
      status = rtm_wait_timeout(rtm, 10 /* seconds */);
      if (status != RTM_OK) {
        fprintf(stderr, "Failed to receive publish reply or subscription data: %s\n", rtm_error_string(status));
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

    fflush(stdout);
    fflush(stderr);

    rtm_wait_timeout(rtm, 2);
  }
}
