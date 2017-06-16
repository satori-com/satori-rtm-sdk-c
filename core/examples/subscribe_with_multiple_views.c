#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <rtm.h>

static char const *endpoint = "YOUR_ENDPOINT";
static char const *appkey = "YOUR_APPKEY";

void pdu_handler(rtm_client_t *client, rtm_pdu_t const *pdu) {
  switch (pdu->action) {
    case RTM_ACTION_SUBSCRIPTION_DATA: {
      char *message;
      while ((message = rtm_iterate(&pdu->message_iterator))) {
        if (0 == strcmp(pdu->subscription_id, "zebras")) {
          printf("Got a zebra: %s\n", message);
        } else {
          printf("Got a count: %s\n", message);
        }
      }
      break;
    }
    case RTM_ACTION_SUBSCRIBE_OK:
      printf("Subscribed to: %s\n", pdu->subscription_id);
      break;
    case RTM_ACTION_SUBSCRIPTION_ERROR:
    case RTM_ACTION_SUBSCRIBE_ERROR:
      fprintf(stderr, "Subscription failed. RTM sent the error %s: %s\n", pdu->error, pdu->reason);
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

  if (rc != RTM_OK) {
    fprintf(stderr, "Failed to connect: %s\n", rtm_error_string(rc));
    goto cleanup;
  }

  printf("Connected to Satori RTM!\n");

  unsigned request_id;
  char const *zebras = "{\"filter\" : \"SELECT * FROM `animals` WHERE who = 'zebra'\", \"subscription_id\" : \"zebras\"}";
  rc = rtm_subscribe_with_body(client, zebras, &request_id);

  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to subscribe: %s\n", rtm_error_string(rc));
    goto cleanup;
  }

  rc = rtm_wait_timeout(client, 10 /* seconds */);
  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to receive subscribe reply: %s\n", rtm_error_string(rc));
    goto cleanup;
  }

  char const *stats = "{\"filter\" : \"SELECT count(*) as count, who FROM `animals` GROUP BY who\", \"subscription_id\" : \"stats\"}";
  rc = rtm_subscribe_with_body(client, stats, &request_id);

  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to subscribe: %s\n", rtm_error_string(rc));
    goto cleanup;
  }

  rc = rtm_wait_timeout(client, 10 /* seconds */);
  if (RTM_OK != rc) {
    fprintf(stderr, "Failed to receive subscribe reply: %s\n", rtm_error_string(rc));
    goto cleanup;
  }

  while (1) {
    rc = rtm_wait_timeout(client, 10 /* seconds */);
    if (rc != RTM_OK && rc != RTM_ERR_TIMEOUT) {
      fprintf(stderr, "Error while waiting for channel data: %s\n", rtm_error_string(rc));
      goto cleanup;
    }
  }
  cleanup:
  rtm_close(client);
  free(client);
  return rc;
}
