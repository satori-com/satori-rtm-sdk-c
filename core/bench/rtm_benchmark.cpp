#include <ctime>
#include <unistd.h>
#include <cstdarg>
#include <benchmark/benchmark_api.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <src/rtm_internal.h>

void BM_json_escape(benchmark::State &state) {
  const char *input = "\nhello\t\t";
  char output[1024];

  while (state.KeepRunning()) {
    _rtm_json_escape(&output[0], 1024, input);
    //benchmark::DoNotOptimize(state.iterations());
  }
}

char* generate_message(int size) {
  char *str = (char *) malloc((size + 1) * sizeof(char));
  for (int i = 0; i < size; i++) {
    str[i] = 'x';
  }
  str[size] = '\0';
  return str;
}


void BM_parse_pdu(benchmark::State &state) {
  const char *tmpl = "{\"action\":\"rtm/publish/ok\",\"id\":42,\"body\":{\"next\":\"1479315802:0\",\"messages\":[\"%s\"]}}";
  char *msg = generate_message(state.range_x());

  char *pdu_text = (char *) malloc(state.range_x() + 256);
  sprintf(pdu_text, tmpl, msg);

  char* pdu_dup = strdup(pdu_text);
  while (state.KeepRunning()) {
    strcpy(pdu_dup, pdu_text);
    rtm_pdu_t pdu = {0};
    rtm_parse_pdu(pdu_dup, &pdu);
  }
}

BENCHMARK(BM_parse_pdu)->Range(8, (50 * 1024));


BENCHMARK_MAIN();
