#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <rtm.h>
#include "../test_credentials.h"

static char const *endpoint = YOUR_ENDPOINT;
static char const *appkey = YOUR_APPKEY;

int main(void) {
  void *memory = malloc(rtm_client_size);
  rtm_client_t *client = rtm_init(memory, &rtm_default_pdu_handler, 0);
  rtm_status rc = rtm_connect(client, endpoint, appkey);

  if (rc != RTM_OK) {
    fprintf(stderr, "Failed to connect: %s\n", rtm_error_string(rc));
    rtm_close(client);
    free(client);
    return rc;
  }
  printf("Connected to Satori RTM!\n");

  rtm_close(client);
  free(client);
  return 0;
}
