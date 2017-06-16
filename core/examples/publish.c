#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <rtm.h>

static char const *endpoint = "YOUR_ENDPOINT";
static char const *appkey = "YOUR_APPKEY";

void pdu_handler(rtm_client_t *client, const rtm_pdu_t *pdu) {
  switch (pdu->action) {
    case RTM_ACTION_PUBLISH_OK:
      printf("Publish confirmed\n");
      break;
    case RTM_ACTION_PUBLISH_ERROR:
      fprintf(stderr, "Failed to publish. RTM replied with the error %s:  %s\n", pdu->error, pdu->reason);
      break;
    default:
      rtm_default_pdu_handler(client, pdu);
      break;
  }
}

int main() {
  void *memory = malloc(rtm_client_size);
  rtm_client_t *client = rtm_init(memory, pdu_handler, 0);
  rtm_status rc = rtm_connect(client, endpoint, appkey);

  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to connect: %s\n", rtm_error_string(rc));
    goto cleanup;
  }

  printf("Connected to Satori RTM!\n");

  unsigned request_id;
  char const *message = "{\"who\":\"zebra\",\"where\":[34.134358, -118.321506]}";
  char const *channelName = "animals";
  rc = rtm_publish_json(client, channelName, message, &request_id);

  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to publish: %s\n", rtm_error_string(rc));
    goto cleanup;
  }

  rc = rtm_wait_timeout(client, 10 /* seconds */);
  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to receive publish reply: %s\n", rtm_error_string(rc));
    goto cleanup;
  }

  goto cleanup;
  cleanup:
  rtm_close(client);
  free(client);
  return rc;
}
