#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <rtm.h>

static char const *endpoint = "wss://myapp.api.satori.com/";
static char const *appkey = "my_appkey";

static char const *channel = "my_channel";

void pdu_handler(rtm_client_t *rtm, rtm_pdu_t const *pdu) {
    switch (pdu->action) {
      case RTM_ACTION_SUBSCRIPTION_DATA: {
        char *message;
        while ((message = rtm_iterate(&pdu->message_iterator))) {
          printf("Got message %s\n", message);
        }
        break;
      }
      case RTM_ACTION_SUBSCRIBE_OK:
        fprintf(stderr, "Subscribed to channel %s\n", pdu->subscription_id);
        break;
      case RTM_ACTION_GENERAL_ERROR:
      case RTM_ACTION_SUBSCRIPTION_ERROR:
      case RTM_ACTION_SUBSCRIBE_ERROR:
        fprintf(stderr, " Error: %s - %s\n", pdu->error, pdu->reason);
        break;
      default:
        break;
    }
}

int main(void) {
    rtm_client_t *rtm = (rtm_client_t *)malloc(rtm_client_size);
    rtm_init(rtm, pdu_handler, 0);
    int rc = rtm_connect(rtm, endpoint, appkey);

    if (rc != RTM_OK) {
        printf("rtm_connect failed with status %d\n", rc);
        goto cleanup;
    }

    printf("Connected to RTM!\n");

    unsigned int ack_id;
    rc = rtm_subscribe(rtm, channel, &ack_id);

    if (rc != RTM_OK) {
        printf("rtm_subscribe failed with status %d\n", rc);
        goto cleanup;
    }

    rc = rtm_wait_timeout(rtm, 10 /* seconds */);
    if (rc != RTM_OK) {
        fprintf(stderr, "Failed to receive publish reply\n");
        goto cleanup;
    }

    rc = rtm_wait_timeout(rtm, 10 /* seconds */);
    if (rc != RTM_OK) {
        fprintf(stderr, "Failed to receive a message from channel\n");
        goto cleanup;
    }

    goto cleanup;
 cleanup:
    rtm_close(rtm);
    free(rtm);
    return rc;
}
