#include <stdlib.h>
#include <stdio.h>
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

int main(int argc, const char *argv[]) {
  rtm_client_t *rtm = (rtm_client_t *)malloc(rtm_client_size);
  unsigned request_id;
  rtm_status rc;

  rc = rtm_connect(rtm, "wss://xxx.api.satori.com/",
                   "<APPKEY>",
                   &rtm_default_pdu_handler, NULL);

  if (rc) {
    fprintf(stderr, "Unable to connect to RTM: %s\n", rtm_error_string(rc));
    free(rtm);
    return rc;
  }

  fprintf(stderr, "Connected to RTM\n");

  rc = rtm_subscribe(rtm, "test", &request_id);
  if (rc) {
    fprintf(stderr, "Unable to subscribe to channel: %s\n", rtm_error_string(rc));
    rtm_close(rtm);
    free(rtm);
    return rc;
  }
  rtm_publish_string(rtm, "test", "Hello world!", NULL);
  for (int i = 0; i < 100; i++) {
    char buffer[1024];
    sprintf(buffer, "This is the index %d", i);
    rtm_publish_string(rtm, "test", buffer, NULL);
  }

  fprintf(stderr, "Subscribed\n");
  sleep(1);

  time_t start_time = time(NULL);
  while (1) {
    rc = rtm_wait(rtm);
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
