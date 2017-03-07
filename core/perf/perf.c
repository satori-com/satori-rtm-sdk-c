#include <ctype.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <src/rtm.h>
#include <sys/time.h>
#include <sysexits.h>
#include <stdbool.h>
#include <mavg.h>
#include <math.h>

#define GET_TS_GRANULARITY 100
#define TRUE 1
#define FALSE 0

void print_usage() {
  printf("Usage: ./perf -e <endpoint> -a <appkey> -s [subscribe|publish|publish-noack] -m <message_size> -c <channel>\n");
}

typedef struct {
  mavg meter;
  ssize_t counter;
  double last_print_ts;
} rtm_stat;

char channel_data_buf[RTM_MAX_MESSAGE_SIZE+1];

struct multiplier {
    char *prefix;
    double mult;
};

struct bench_params {
  char *endpoint;
  char *appkey;
  char *scenario;
  char *channel;
  double duration;
  int message_size;
};

static struct multiplier s_multiplier[] = {
    { "ms", 0.001 }, { "millisecond", 0.001 }, { "milliseconds", 0.001 },
    { "s", 1 }, { "second", 1 }, { "seconds", 1 },
    { "m", 60 }, { "min", 60 }, { "minute", 60 }, { "minutes", 60 },
    { "h", 3600 }, { "hr", 3600 }, { "hour", 3600 }, { "hours", 3600 }
};

static const char* scenarios[] = { "publish-noack", "publish", "subscribe" };

static double
parse_with_multipliers(const char *option, char *str, struct multiplier *ms,
                       int n) {
    char *endptr;
    double value = strtod(str, &endptr);
    if(endptr == str) {
        return -1;
    }
    for(; n > 0; n--, ms++) {
        if(strcmp(endptr, ms->prefix) == 0) {
            value *= ms->mult;
            endptr += strlen(endptr);
            break;
        }
    }
    if(*endptr) {
        fprintf(stderr, "Unknown prefix \"%s\" in %s\n", endptr, str);
        return -1;
    }
    if(!isfinite(value)) {
        fprintf(stderr, "Option %s parses to infinite value\n", option);
        return -1;
    }
    return value;
}

static bool is_valid_scenario(char const *s) {
  int n = (int) sizeof(scenarios) / sizeof(scenarios[0]);
  int i = 0;
  for (; i < n; i++) {
    if (0 == strcmp(scenarios[i], s)) {
      return true;
    }
  }
  return false;
}

static double ts_now() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec + ((double) tv.tv_usec / 1000000);
}

static void generate_message(char* msg, int size) {
  int i = 0;
  for (; i < size; i++) {
    msg[i] = 'a' + (rand() % 26);
  }
  msg[size] = '\0';
}

static rtm_stat create_stat() {
  rtm_stat stat = {.counter = 0, .last_print_ts = 0.0};
  mavg_init(&stat.meter, ts_now(), 3.0);
  return stat;
}

static double bump(rtm_stat *stat) {
  stat->counter++;

  // avoid calling syscall gettimeofday on each bump
  if (0 != stat->counter % GET_TS_GRANULARITY) {
    return -1;
  }

  double now = ts_now();
  mavg_bump(&stat->meter, now, stat->counter);
  stat->counter = 0;

  return now;
}

static void maybe_print(rtm_stat *stat, double now, char const *fmt) {
  if (now <= 0) {
    return;
  }
  double report_interval = 5.0; // report each 5 sec
  if ((now - stat->last_print_ts) < report_interval) {
    return;
  }
  fprintf(stdout, fmt, mavg_per_second(&stat->meter, now));
  fflush(stdout);
  stat->last_print_ts = now;
}

static bool should_run(rtm_stat *stat, double start_at, double duration) {
  if (duration < stat->last_print_ts - start_at) {
    return FALSE;
  }
  double maybe_now = bump(stat);
  if (maybe_now < 0) {
    return TRUE;
  }
  stat->last_print_ts = maybe_now;
  return (maybe_now - start_at <= duration);
}

static void calc_publish_ok_stats(rtm_client_t *rtm, const rtm_pdu_t *pdu) {
  if (0 == strcmp(pdu->action, "rtm/publish/ok")) {
    rtm_stat* stat = (rtm_stat *) rtm_get_user_context(rtm);
    double now = bump(stat);
    maybe_print(stat, now, "publish-ok %.1f↓ rps\n");
  }
}

static void on_subscription_data(rtm_client_t *rtm, const char *subscription_id, const char *message) {
  rtm_stat* stat = (rtm_stat *) rtm_get_user_context(rtm);

  double now = bump(stat);
  maybe_print(stat, now, "subscription-data %.1f↓ rps\n");
}

void calc_subscription_data_stats(rtm_client_t *rtm, const rtm_pdu_t *pdu) {
  if (0 != strcmp(pdu->action, "rtm/subscription/data")) {
    return;
  }
  rtm_parse_subscription_data(rtm, pdu, channel_data_buf, RTM_MAX_MESSAGE_SIZE,
      &on_subscription_data);
}

static int bench_subscribe(struct bench_params *opts) {
  rtm_stat stat = create_stat();
  rtm_client_t* rtm = (rtm_client_t *) alloca(rtm_client_size);

  int rc = rtm_connect(rtm, opts->endpoint, opts->appkey, &calc_subscription_data_stats, &stat);
  if (RTM_OK != rc) {
    return rc;
  }

  unsigned request_id;
  int buf_size = 256;
  char body[buf_size];
  sprintf(body, "{\"channel\":\"%s\",\"fast_forward\":true}", opts->channel);

  rc = rtm_subscribe_with_body(rtm, body, &request_id);

  double start_ts = ts_now();
  rtm_stat run_stat = create_stat();

  while (rc == RTM_OK || rc == RTM_ERR_TIMEOUT) {
    if (!should_run(&run_stat, start_ts, opts->duration)) {
      return RTM_OK;
    }
    rc = rtm_wait_timeout(rtm, 1);
  }
  return rc;
}

static int bench_publish(struct bench_params* opts) {
  assert(0 < opts->message_size);

  rtm_stat ack_stat = create_stat();
  rtm_stat publish_stat = create_stat();
  unsigned id;
  unsigned *ack_id = NULL;
  char message[opts->message_size+1];

  rtm_client_t* rtm = (rtm_client_t *) alloca(rtm_client_size);

  int rc = rtm_connect(rtm, opts->endpoint, opts->appkey, &calc_publish_ok_stats, &ack_stat);
  if (RTM_OK != rc) {
    return rc;
  }

  generate_message(message, opts->message_size);

  if (0 == strcmp(opts->scenario, "publish")) {
    ack_id = &id;
  }

  double start_ts = ts_now();
  rtm_stat run_stat = create_stat();

  while (rc == RTM_OK || rc == RTM_WOULD_BLOCK) {
    if (!should_run(&run_stat, start_ts, opts->duration)) {
      return RTM_OK;
    }

    rc = rtm_publish_string(rtm, opts->channel, message, ack_id);

    double now = bump(&publish_stat);
    maybe_print(&publish_stat, now, "publish %.1f↑ rps\n");

    while (rc == RTM_OK) {
      rc = rtm_poll(rtm);
    }
  }

  return rc;
}

static int do_bench(struct bench_params *opts) {

  fprintf(stdout, "Run benchmark:\n\tscenario: %s\n\tendpoint: %s\n\tappkey: %s\n\tchannel: %s\n\tmessage_size: %d\n\tduration: %.1f seconds\n",
      opts->scenario,
      opts->endpoint,
      opts->appkey,
      opts->channel,
      opts->message_size,
      opts->duration
  );
  fflush(stdout);

  char const *publish_prefix = "publish";
  if (0 == strncmp(opts->scenario, publish_prefix, strlen(publish_prefix))) {
    return bench_publish(opts);
  }
  return bench_subscribe(opts);
}

int main(int argc, char *argv[]) {
  static struct option long_options[] = {
    {"endpoint",     required_argument, 0,  'e' },
    {"appkey",       required_argument, 0,  'a' },
    {"channel",      required_argument, 0,  'c' },
    {"message_size", required_argument, 0,  'm' },
    {"scenario",     required_argument, 0,  's' },
    {"duration",     required_argument, 0,  'd' },
    {"help",         no_argument,       0,  'h' },
    {0,              0,                 0,  0   }
  };

  struct bench_params bench_params = {
    .message_size = 128, // 128 byte messages by default
    .duration = 60, // 60 seconds by default
    .endpoint = NULL,
    .appkey = NULL,
    .scenario = NULL,
    .channel = NULL
  };

  int long_index = 0;
  int opt;

  while ((opt = getopt_long(argc, argv, "e:a:c:m:s:hd:", long_options, &long_index )) != -1) {
    char *option = argv[optind];
    switch (opt) {
      case 'e':
        bench_params.endpoint = strdup(optarg);
        break;
      case 'a':
        bench_params.appkey = strdup(optarg);
        break;
      case 'm':
        bench_params.message_size = strtol(optarg, NULL, 0);
        break;
      case 's':
        bench_params.scenario = strdup(optarg);
        if (!is_valid_scenario(bench_params.scenario)) {
          print_usage();
          exit(EXIT_FAILURE);
        }
        break;
      case 'c':
        bench_params.channel = strdup(optarg);
        break;
      case 'h':
        print_usage();
        exit(0);
        break;
      case 'd':
        bench_params.duration = parse_with_multipliers(
            option, optarg, s_multiplier,
            sizeof(s_multiplier) / sizeof(s_multiplier[0]));

        if(bench_params.duration < 0.0) {
          fprintf(stderr, "Expected non-negative --duration=%s\n", optarg);
          exit(EX_USAGE);
        }

        break;
      default:
        print_usage();
        exit(EX_USAGE);
        break;
    }
  }

  if (NULL == bench_params.endpoint) {
      fprintf(stderr, "endpoint is a mandatory parameter\n");
      print_usage();
      exit(EX_USAGE);
  }

  if (NULL == bench_params.appkey) {
      fprintf(stderr, "appkey is a mandatory parameter\n");
      print_usage();
      exit(EX_USAGE);
  }

  if (NULL == bench_params.scenario) {
      fprintf(stderr, "scenario is a mandatory parameter\n");
      print_usage();
      exit(EX_USAGE);
  }

  if (NULL == bench_params.channel) {
    bench_params.channel = strdup("channel");
  }

  srand((int) ts_now());

  int rc = do_bench(&bench_params);

  free(bench_params.channel);
  free(bench_params.endpoint);
  free(bench_params.appkey);
  free(bench_params.scenario);

  if (RTM_OK != rc) {
    fprintf(stderr, "non-zero rtm code (%d)\n", rc);
  }

  return rc;
}

