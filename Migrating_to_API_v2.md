
# Breaking changes in v2.0.0

## rtm_init

`rtm_connect(rtm_client, endpoint, appkey, callback, user_context)` was split into
rtm_init and rtm_connect to allow configuration code to take place before
connecting to RTM. New API also doesn't force client code to cast a buffer
to `rtm_client_t *`, improving type safety.

v1:

```
rtm_client_t *client = (rtm_client_t *)malloc(rtm_client_size);
my_application_state state = {0};
rtm_status = rtm_connect(client, "YOUR_ENDPOINT", "YOUR_APPKEY", my_pdu_handler, &state);
```

v2:

```
void *memory = malloc(rtm_client_size);
my_application_state state = {0};
rtm_client_t *client = rtm_init(memory, pdu_handler, &state);
rtm_status rc = rtm_connect(client, "YOUR_ENDPOINT", "YOUR_APPKEY");
```

## Setting connection timeout

In v1 API you had to use a global variable `rtm_connect_timeout`. In v2 there's
a function `void rtm_set_connection_timeout(rtm_client_t *rtm, unsigned
timeout_in_seconds)` that you can call after `rtm_init` and before
`rtm_connect`.

## PDU handler

In v1 the pdu handler function was taking a `const rtm_pdu_t *pdu` which was a struct that had an action string, an unsigned int id and a body as `char *`. That is, the pdu was parsed by the SDK one layer deep, but if you were interested in something more specific than that, e.g. a "reason" field inside the body of a "rtm/subscribe/error" PDU, you were left on your own with parsing the body.

In v2 there are two types of pdu handlers: one takes takes a fully parsed PDU and the other (called raw PDU handler) takes an unparsed PDU as `char *`. Using a raw PDU handler is useful if for example you already have a JSON library included in your project or you're using C Core SDK from a language that already has it in the standard library, like Objective C.

Here's how to use the PDU handler in v2:

```
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
```

Note that the action field in rtm_pdu_t is now of type `enum rtm_action_t` instead of `char *`, which allows matching it with a `switch` statement and enables the compiler to catch typos.

In `RTM_ACTION_PUBLISH_ERROR` clause we're printing pdu->error and pdu->reason.
We can safely access pdu->error and pdu->reason precisely because at that point
we know that the PDU describes a publish error. Doxygen string for rtm_pdu_t
describes what fields are available for which PDUs:
https://satori-com.github.io/satori-rtm-sdk-c/rtm_8h.html#a76e6947b67e9c81dbafe8580611256e7.

An attempt to access a field that's not available for the action of a given PDU
will result in undefined behavior.

## Getting messages

In v1 there was a separate callback type `rtm_message_handler_t` for getting messages. In v2 getting messages is done inline in the pdu handler:

```
void pdu_handler(rtm_client_t *client, rtm_pdu_t const *pdu) {
  switch (pdu->action) {
    case RTM_ACTION_SUBSCRIPTION_DATA: {
      char *message;
      while ((message = rtm_iterate(&pdu->message_iterator))) {
        printf("Got message: %s\n", message);
      }
      break;
    }
    ...
  }
}
```