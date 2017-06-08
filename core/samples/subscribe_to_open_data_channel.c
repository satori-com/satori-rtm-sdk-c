#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rtm.h>

static char const *endpoint = "wss://open-data.api.satori.com";
static char const *appkey = "YOUR_APPKEY";
static char const *channel = "YOUR_CHANNEL";

struct program_state_t {
  int subscribe_ok;
};

void pdu_handler(rtm_client_t *rtm, const rtm_pdu_t *pdu) {
  struct program_state_t *program_state = (struct program_state_t *)rtm_get_user_context(rtm);

  switch(pdu->action) {
    case RTM_ACTION_SUBSCRIBE_OK:
      program_state->subscribe_ok = 1;
      return;
    case RTM_ACTION_SUBSCRIBE_ERROR:
      program_state->subscribe_ok = 0;
      return;
    case RTM_ACTION_SUBSCRIPTION_DATA:
      rtm_default_pdu_handler(rtm, pdu);
      return;
    default:
      return;
  }
}

int main(void) {
  rtm_client_t *rtm = (rtm_client_t *)malloc(rtm_client_size);

  rtm_status status;
  struct program_state_t program_state = {0};

  rtm_init(rtm, &pdu_handler, &program_state);
  status = rtm_connect(rtm, endpoint, appkey);

  if (status != RTM_OK) {
    fprintf(stderr, "Connecting to RTM failed: %s\n", rtm_error_string(status));
    free(rtm);
    return status;
  }

  unsigned request_id;
  status = rtm_subscribe(rtm, channel, &request_id);
  if (status != RTM_OK) {
    fprintf(stderr, "Unable to send subscribe request: %s\n", rtm_error_string(status));
    rtm_close(rtm);
    free(rtm);
    return status;
  }

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

  if (!program_state.subscribe_ok) {
    fprintf(stderr, "Subscribe reply was an error\n");
    rtm_close(rtm);
    free(rtm);
    return status;
  }

  printf("Successfully subscribed to %s\n", channel);
  printf("Press CTRL-C to exit\n");

  while (1) {
    status = rtm_wait_timeout(rtm, 10 /* seconds */);
    if (status == RTM_OK || status == RTM_ERR_TIMEOUT) {
      continue;
    }
    fprintf(stderr, "Error while waiting for channel data: %s\n", rtm_error_string(status));
    rtm_close(rtm);
    free(rtm);
    return status;
  }

  rtm_close(rtm);
  free(rtm);
}