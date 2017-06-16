/**
 * @file
 * @brief RTM CORE SDK documentation.
 *
 * @details
 *
 * This Core SDK is a very low level to the RTM service.
 *
 * @code{.c}
 * // allocate some memory to store the client
 * void *memory = malloc(rtm_client_size);
 * rtm_client_t *rtm = rtm_init(memory, rtm_default_pdu_handler, 0);
 * // connect to RTM
 * int rc = rtm_connect(rtm, endpoint, appkey);
 * if (rc != RTM_OK) {
 *     printf("rtm_connect failed with status %d\n", rc);
 *     exit(1);
 * }
 * // publish message
 * rc = rtm_publish_string(rtm, "channel", "Hello, World!", NULL);
 * if (rc != RTM_OK) {
 *     printf("rtm_publish_string failed with status %d\n", rc);
 *     exit(1);
 * }
 * rtm_close(rtm);
 * @endcode
 */
#ifndef CORE_RTM_H__INCLUDED
#define CORE_RTM_H__INCLUDED
#include <stddef.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(rtm_core_sdk_EXPORTS) && defined(_WIN32)
#define RTM_API __declspec(dllexport)
#elif defined(_WIN32)
#define RTM_API __declspec(dllimport)
#else
#define RTM_API
#endif

/**
 * @brief Maximum size of a channel name.
 */
#define RTM_MAX_CHANNEL_SIZE (256)

/**
 * @brief Maximum size of a message.
 */
#define RTM_MAX_MESSAGE_SIZE (65536)

/**
 * @brief RTM path.
 */
#define RTM_PATH ("/v2")


/**
 * @brief Maximum size of the endpoint parameter.
 */
#define RTM_MAX_ENDPOINT_SIZE (256)

/**
 * @brief Maximum size of the appkey parameter.
 */
#define RTM_MAX_APPKEY_SIZE (32)

/**
 * @brief Maximum size of the role name parameter.
 */
#define RTM_MAX_ROLE_NAME_SIZE (512)

/**
 * @brief Expected size of the authentication hash parameter in bytes.
 */
#define RTM_AUTHENTICATION_HASH_SIZE (24)

/**
 * @brief The set of all possible actions that PDUs incoming from RTM can have
 */
enum rtm_action_t {
    RTM_ACTION_UNKNOWN = 0,
    RTM_ACTION_AUTHENTICATE_ERROR,
    RTM_ACTION_AUTHENTICATE_OK,
    RTM_ACTION_DELETE_ERROR,
    RTM_ACTION_DELETE_OK,
    RTM_ACTION_GENERAL_ERROR,
    RTM_ACTION_HANDSHAKE_ERROR,
    RTM_ACTION_HANDSHAKE_OK,
    RTM_ACTION_PUBLISH_ERROR,
    RTM_ACTION_PUBLISH_OK,
    RTM_ACTION_READ_ERROR,
    RTM_ACTION_READ_OK,
    RTM_ACTION_SEARCH_DATA,
    RTM_ACTION_SEARCH_ERROR,
    RTM_ACTION_SEARCH_OK,
    RTM_ACTION_SUBSCRIBE_ERROR,
    RTM_ACTION_SUBSCRIBE_OK,
    RTM_ACTION_SUBSCRIPTION_DATA,
    RTM_ACTION_SUBSCRIPTION_ERROR,
    RTM_ACTION_SUBSCRIPTION_INFO,
    RTM_ACTION_UNSUBSCRIBE_ERROR,
    RTM_ACTION_UNSUBSCRIBE_OK,
    RTM_ACTION_WRITE_ERROR,
    RTM_ACTION_WRITE_OK,
    RTM_ACTION_SENTINEL
};

/**
 * @brief SDK uses this type to return collections of strings,
 *        for example messages in subscription_data PDUs.
 *        User code repeatedly calls ::rtm_iterate with the
 *        iterator, getting all messages one by one.
 *
 * @see ::rtm_iterate
 */
typedef struct {
    char *position;
} rtm_list_iterator_t;

/**
 * @brief get next element in iterator or NULL if there are none
 */
RTM_API char *rtm_iterate(rtm_list_iterator_t const *iterator);

/**
 * @brief Structure containing information about the received PDU.
 *
 *  Extra fields availability:
 *
 *        Action              | Fields
 *        ------------------- | -------------
 *        UNKNOWN             | body
 *        AUTHENTICATE_ERROR  | error, reason
 *        GENERAL_ERROR       | error, reason
 *        DELETE_ERROR        | error, reason
 *        HANDSHAKE_ERROR     | error, reason
 *        PUBLISH_ERROR       | error, reason
 *        READ_ERROR          | error, reason
 *        WRITE_ERROR         | error, reason
 *        SEARCH_ERROR        | error, reason
 *        SUBSCRIBE_ERROR     | error, reason
 *        UNSUBSCRIBE_ERROR   | error, reason
 *        SUBSCRIPTION_ERROR  | subscription_id, error, reason
 *        SUBSCRIPTION_INFO   | subscription_id, info, reason
 *        SUBSCRIPTION_DATA   | subscription_id, message_iterator, position
 *        SUBSCRIBE_OK        | subscription_id, position
 *        UNSUBSCRIBE_OK      | subscription_id, position
 *        AUTHENTICATE_OK     | ---
 *        HANDSHAKE_OK        | nonce
 *        PUBLISH_OK          | position
 *        DELETE_OK           | position
 *        WRITE_OK            | position
 *        READ_OK             | message, position
 *        SEARCH_DATA         | channel_iterator
 *        SEARCH_OK           | channel_iterator
 */
typedef struct _rtm_pdu {
    unsigned request_id;
    enum rtm_action_t action;
    union {
        struct {
            union {
              char const *error;
              char const *info;
            };
            char const *reason;
        };
        struct {
            char const *position;
            char const *subscription_id;
            union {
                char const *message;
                rtm_list_iterator_t message_iterator;
            };
        };
        char const *body;
        char const *nonce;
        rtm_list_iterator_t channel_iterator;
    };
} rtm_pdu_t;

/**
 * @brief Opaque rtm client structure.
 */
typedef struct _rtm_client rtm_client_t;

/**
 * @brief Type of callback function invoked when client receives messages from RTM.
 *
 * @note when ::rtm_init is called, a pointer to a user defined structure
 * can be set. You can get this value from @p rtm in the context of this
 * callback by calling ::rtm_get_user_context:
 *
 * @code{.c}
 * void my_message_callback(rtm_client_t *rtm, const char *subscription_id,
 *                          const char *message) {
 *    my_context *context = (my_context *) rtm_get_user_context(rtm);
 *    context->message_count++;
 *    ...
 * }
 * @endcode
 *
 * @see ::rtm_default_message_handler for details.
 * @see ::rtm_get_user_context
 * @see ::rtm_init
 */
typedef void(rtm_message_handler_t)(rtm_client_t *rtm, const char *subscription_id,
             const char *message);

/**
 * @brief Type of callback function invoked when client receives PDU from RTM.
 *
 * @note when ::rtm_init is called, a pointer to a user defined structure can be
 * set. You can get this value from @p rtm in the context of this callback by 
 * calling ::rtm_get_user_context:
 *
 * @code{.c}
 * void my_pdu_callback(rtm_client_t *rtm, const rtm_pdu_t *pdu) {
 *    my_context *context = (my_context *) rtm_get_user_context(rtm);
 *    context->event_count++;
 *    ...
 * }
 * @endcode
 *
 * @see ::rtm_default_pdu_handler for details.
 * @see ::rtm_init
 * @see ::rtm_get_user_context
 *
 */
typedef void(rtm_pdu_handler_t)(rtm_client_t *rtm, const rtm_pdu_t *pdu);
typedef void(rtm_raw_pdu_handler_t)(rtm_client_t *rtm, char const *raw_pdu);

/**
 * @brief Global error logging function.
 */
typedef void(*rtm_error_logger_t)(const char *message);

/**
 * @brief Type used internally to report errors.
 *
 * The values can be used to diagnose errors that happen while interacting with 
 * c core.
 */
typedef enum {
    RTM_OK = 0,                   /*!< No error.                                     */
    RTM_WOULD_BLOCK,              /*!< The operation would be a blocking IO
                                       operation                                     */
    RTM_ERR_PARAM = -99,          /*!< One of the parameters passed to the function
                                       is incorrect                                  */
    RTM_ERR_PARAM_INVALID = -98,  /*!< A parameter of the function is invalid        */
    RTM_ERR_CONNECT = -97,        /*!< The client could not connect to RTM           */
    RTM_ERR_NETWORK = -96,        /*!< An unexpected network error occurred          */
    RTM_ERR_CLOSED = -95,         /*!< The connection is closed                      */
    RTM_ERR_READ = -94,           /*!< An error occurred while receiving data from
                                       RTM                                           */
    RTM_ERR_WRITE = -93,          /*!< An error occurred while sending data to RTM   */
    RTM_ERR_PROTOCOL = -92,       /*!< An error occurred in the protocol layer       */
    RTM_ERR_TLS = -91,            /*!< An unexpected error happened in the TLS layer */
    RTM_ERR_TIMEOUT = -90         /*!< The operation timed out                       */
} rtm_status;

/**
 * @brief Size of ::rtm_client_t in bytes.
 */
RTM_API extern const size_t rtm_client_size;

/**
 * @brief Global pointer to the rtm_error_logger() function. The default value
 * is @c ::rtm_default_error_logger.
 */
extern void(*rtm_error_logger)(const char *message);

/**
 * @brief Default error handler.
 *
 * This handler sends all messages to stderr.
 *
 * @param[in] message to log as a zero terminated string.
 */
void rtm_default_error_logger(const char *message);

/**
 * @brief Default message handler prints all messages to stdout.
 *
 * @param[in] rtm instance of the client
 * @param[in] channel name of the channel
 * @param[in] message message to output
 */
void rtm_default_message_handler(rtm_client_t *rtm, const char *channel,
                                 const char *message);

/**
 * @brief Default PDU handler prints all PDUs to stdout.
 *
 * @param[in] rtm instance of the client
 * @param[in] pdu the ::rtm_pdu_t to process
 */
RTM_API void rtm_default_pdu_handler(rtm_client_t *rtm, const rtm_pdu_t *pdu);

/**
 * @brief Returns current WS ping interval (sec)
 *
 * @param[in] rtm instance of the client
 *
 * @return current ping interval
 */
RTM_API time_t rtm_get_ws_ping_interval(rtm_client_t *rtm);

/**
 * @brief Sets the given connection timeout in seconds. Default is 5 seconds.
 *
 * @param[in] rtm instance of the client
 * @param[in] timeout_in_seconds new timeout value
 *
 */
RTM_API void rtm_set_connection_timeout(rtm_client_t *rtm, unsigned timeout_in_seconds);

/**
 * @brief Sets new WS ping interval. A ws ping frame will be perodically sent to server
 * to avoid connection refusing. Default: 45 (sec)
 *
 * @param[in] rtm instance of the client
 * @param[in] ws_ping_interval new interval value (sec)
 *
 */
RTM_API void rtm_set_ws_ping_interval(rtm_client_t *rtm, time_t ws_ping_interval);

/**
 * @brief Initialize an instance of rtm_client_t
 *
 * @param[in] memory a buffer of size RTM_CLIENT_SIZE
 * @param[in] pdu_handler the callback for all PDUs
 * @param[in] user_context an opaque user specified data associated with this 
 *            RTM object
 *
 *
 * @return initialized rtm_client_t object
 *
 * @see ::rtm_close
 * @see ::rtm_get_user_context
 *
 * @note If you choose to work with unparsed PDUs, pass null as pdu_handler
 *       here and then use ::rtm_set_raw_pdu_handler.
 *
 */
RTM_API rtm_client_t *rtm_init(
  void *memory,
  rtm_pdu_handler_t *pdu_handler,
  void *user_context);

/**
 * @brief Initialize an instance of rtm_client_t and connects to RTM.
 *
 * @param[in] rtm instance of the client
 * @param[in] endpoint endpoint for the RTM Service.
 * @param[in] appkey application key to the RTM Service.
 *
 * @note The @p endpoint must be a well formed URL
 *      <tt>"wss://xxx.api.satori.com/"</tt>
 *
 *
 * @return the status of the operation
 * @retval RTM_OK if the connection is established
 * @retval RTM_ERR_* if the connection failed.
 *
 * @see ::rtm_close
 * @see ::rtm_get_user_context
 */
RTM_API rtm_status rtm_connect(rtm_client_t *rtm,
                       const char *endpoint,
                       const char *appkey);

/**
 * @brief Set the handler for not yet parsed PDUs
 *
 * @param[in] rtm instance of the client
 * @param[in] handler pointer to a function of type (rtm_client_t *rtm, char const *raw_pdu) -> void
 *
 * @note After this handler is called, raw_pdu will be parsed by the SDK and
 *       the result will be passed to pdu_handler which was provided to
 *       ::rtm_init function. If (non-raw) pdu_handler was null, that parsing
 *       doesn't happen and you're free to cast raw_pdu to non-const char*
 *       and modify it (for example if your json parser works in-place).
 *
 */
RTM_API void rtm_set_raw_pdu_handler(rtm_client_t *rtm, rtm_raw_pdu_handler_t *handler);

/**
 * @brief Enable logging of incoming and outcoming PDUs.
 *
 * @param[in] rtm instance of the client
 */
RTM_API void rtm_enable_verbose_logging(rtm_client_t *rtm);

/**
 * @brief Disable logging of incoming and outcoming PDUs.
 *
 * @param[in] rtm instance of the client
 */
RTM_API void rtm_disable_verbose_logging(rtm_client_t *rtm);

/**
 * @brief Close an RTM connection.
 *
 * This method gracefully terminating connection to RTM. This method
 * doesn't @p free memory allocated for client.
 *
 * It is safe to call this function from pdu handlers to terminate
 * the connection on e.g., errors.
 *
 * @warning Do not use the object after calling this function.
 *
 * @param[in] rtm instance of the client
 */
RTM_API void rtm_close(rtm_client_t *rtm);

/**
 * @brief Send the handshake request to obtain nonce from the server.
 *
 * Performs initial negotiation to obtain a nonce from the server
 * before the client can send the final authentication request.
 *
 * RTM reply will have same identifier as value of @p ack_id.
 *
 * @param[in] rtm instance of the client
 * @param[in] role name of role
 * @param[out] ack_id the id of the message sent.
 *
 * @return the status of the operation
 * @retval RTM_OK the operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
 */
RTM_API rtm_status rtm_handshake(rtm_client_t *rtm,
                         const char *role, unsigned *ack_id);

/**
 * @brief Send the authenticate request to establish the identity of
 * the client.
 *
 * RTM reply will have same identifier as value of @p ack_id.
 *
 * @param[in] rtm instance of the client.
 * @param[in] role_secret a secret token from Dev Portal.
 * @param[in] nonce from handshare request.
 * @param[out] ack_id the id of the message sent.
 *
 * @return the status of the operation
 * @retval RTM_OK the operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
 */

RTM_API rtm_status rtm_authenticate(rtm_client_t *rtm, const char *role_secret, const char *nonce, unsigned *ack_id);



/**
 * @brief Publish the well-formed JSON string to RTM.
 *
 * RTM reply will have same identifier as value of @p ack_id.
 * If @p ack_id is @p null then no reply from RTM is sent.
 *
 * @param[in] rtm instance of the client
 * @param[in] channel name of the channel
 * @param[in] json message
 * @param[out] ack_id (\e optional) the id of the message sent.
 *
 * @return the status of the operation
 * @retval RTM_OK the operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
 */
RTM_API rtm_status rtm_publish_json(rtm_client_t *rtm, const char *channel,
                            const char *json, unsigned *ack_id);

/**
 * @brief Publish the string to RTM.
 *
 * Published string will be escaped before transmission.
 *
 * RTM reply will have same identifier as value of @p ack_id.
 * If @p ack_id is @p null then no reply from RTM is sent.
 *
 * @param[in] rtm instance of the client
 * @param[in] channel name of the channel
 * @param[in] string the message to send.
 * @param[out] ack_id (\e optional) the id of the message sent.
 *
 * @return the status of the operation
 * @retval RTM_OK operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
 */
RTM_API rtm_status rtm_publish_string(rtm_client_t *rtm, const char *channel,
                              const char *string, unsigned *ack_id);

/**
 * @brief Subscribe to a specific channel.
 *
 * RTM reply will have same identifier as value of @p ack_id.
 * If @p ack_id is @p null then no reply from RTM is sent.
 *
 * @param[in] rtm instance of the client
 * @param[in] channel name of the channel
 * @param[out] ack_id (\e optional) the id of the message sent.
 *
 * @return the status of the operation
 * @retval RTM_OK operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
 */
RTM_API rtm_status rtm_subscribe(rtm_client_t *rtm, const char *channel,
                         unsigned *ack_id);
/**
 * @brief Subscribe with specifying a full body of subscribe PDU request.
 *
 * RTM reply will have same identifier as value of @p ack_id.
 * If @p ack_id is @p null then no reply from RTM is sent.
 *
 * @param[in] rtm instance of the client.
 * @param[in] body of subscribe request PDU as JSON string.
 * @param[out] ack_id (\e optional) the id of the message sent.
 *
 * @return the status of the operation
 * @retval RTM_OK operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
 */
RTM_API rtm_status rtm_subscribe_with_body(rtm_client_t *rtm, const char *body,
                                   unsigned *ack_id);

/**
 * @brief Unsubscribe from a channel.
 *
 * RTM reply will have same identifier as value of @p ack_id.
 * If @p ack_id is @p null then no reply from RTM is sent.
 *
 * @param[in] rtm instance of the client
 * @param[in] channel name of the channel
 * @param[out] ack_id (\e optional) the id of the message sent.
 *
 * @return the status of the operation
 * @retval RTM_OK operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
 */
RTM_API rtm_status rtm_unsubscribe(rtm_client_t *rtm, const char *channel,
                           unsigned *ack_id);

/**
 * @brief Parse string as top-level PDU object.
 *
 * @warning method modifies original JSON string.
 *
 * @param[in] json string.
 * @param[out] pdu_out parsed PDU.
 */
RTM_API void rtm_parse_pdu(char *json, rtm_pdu_t *pdu_out);

/**
 * @brief Read the latest published message.
 *
 * RTM reply will have same identifier as value of @p ack_id.
 *
 * @param[in] rtm instance of the client
 * @param[in] channel name of the channel
 * @param[out] ack_id the id of the message sent.
 *
 * @return the status of the operation
 * @retval RTM_OK operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
 */
RTM_API rtm_status rtm_read(rtm_client_t *rtm, const char *channel, unsigned *ack_id);

/**
 * @brief Read the latest published message with specifying a full body of read PDU
 * request.
 *
 * RTM reply will have same identifier as value of @p ack_id.
 *
 * @param[in] rtm instance of the client
 * @param[in] body of read request PDU as JSON string.
 * @param[out] ack_id the id of the message sent.
 *
 * @return the status of the operation
 * @retval RTM_OK operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
 */
RTM_API rtm_status rtm_read_with_body(rtm_client_t *rtm, const char *body, unsigned *ack_id);

/**
 * @brief Send a websocket ping frame.
 *
 * @return the status of the operation
 * @retval RTM_OK operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
*/
RTM_API rtm_status rtm_send_ws_ping(rtm_client_t *rtm);

/**
 * @brief Write the string value to a specific channel.
 *
 * RTM reply will have same identifier as value of @p ack_id.
 * If @p ack_id is @p null then no reply from RTM is sent.
 *
 * @param[in] rtm instance of the client
 * @param[in] key name of the channel
 * @param[in] string the message to send.
 * @param[out] ack_id (\e optional) the id of the message sent.
 *
 * @return the status of the operation
 * @retval RTM_OK operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
 * @see ::rtm_publish_string
 */
RTM_API rtm_status rtm_write_string(rtm_client_t *rtm, const char *key, const char *string,
    unsigned *ack_id);

/**
 * @brief Write the well-formed JSON value to a specific channel.
 *
 * RTM reply will have same identifier as value of @p ack_id.
 * If @p ack_id is @p null then no reply from RTM is sent.
 *
 * @param[in] rtm instance of the client
 * @param[in] key name of the channel
 * @param[in] json message
 * @param[out] ack_id (\e optional) the id of the message sent.
 *
 * @return the status of the operation
 * @retval RTM_OK operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
 * @see ::rtm_publish_json
 */
RTM_API rtm_status rtm_write_json(rtm_client_t *rtm, const char *key, const char *json,
    unsigned *ack_id);

/**
 * @brief Delete the value of a specific channel.
 *
 * @note same as @p rtm_publish with message @p null
 *
 * RTM reply will have same identifier as value of @p ack_id.
 * If @p ack_id is @p null then no reply from RTM is sent.
 *
 * @param[in] rtm instance of the client
 * @param[in] key name of the channel
 * @param[out] ack_id (\e optional) the id of the message sent.
 *
 * @return the status of the operation
 * @retval RTM_OK operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
 */
RTM_API rtm_status rtm_delete(rtm_client_t *rtm, const char *key, unsigned *ack_id);

/**
 * @brief Search all channels with a given prefix.
 *
 * RTM replies will have same identifier as value of @p ack_id. RTM could send
 * several search responses with same identifier.
 *
 * @param[in] rtm instance of the client
 * @param[in] prefix of the channels.
 * @param[out] ack_id the id of the message sent.
 *
 * @return the status of the operation
 * @retval RTM_OK operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
 */
RTM_API rtm_status rtm_search(rtm_client_t *rtm, const char *prefix, unsigned *ack_id);

/**
 * @brief Send a raw PDU as well-formed JSON string.
 *
 * @param[in] rtm instance of the client
 * @param[in] json PDU as JSON string.
 *
 * @return the status of the operation
 * @retval RTM_OK operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
 */
RTM_API rtm_status rtm_send_pdu(rtm_client_t *rtm, const char *json);

/**
 * @brief Wait for any PDUs and execute the user's callbacks.
 *
 * This method will return after at least one message is processed or an error
 * occurs. It can be used in a tight loop without consuming CPU resources when
 * there is no data to read.
 *
 * @param[in] rtm instance of the client
 *
 * @return the status of the operation
 * @retval RTM_OK operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
 */
RTM_API rtm_status rtm_wait(rtm_client_t *rtm);

/**
 * @brief Wait with timeout for any PDUs and execute the user's callbacks.
 *
 * @param[in] rtm instance of the client
 * @param[in] timeout_in_seconds in seconds
 *
 * @return the status of the operation
 * @retval RTM_OK operation succeeded
 * @retval RTM_ERR_* an error occurred
 *
 * @see ::rtm_status for detailed error codes
 */
RTM_API rtm_status rtm_wait_timeout(rtm_client_t *rtm, int timeout_in_seconds);

/**
 * @brief Poll the underlying socket for any PDUs and execute the user's
 * callbacks.
 *
 * rtm_poll is the internal IO loop.
 *
 * @param[in] rtm instance of the client
 *
 * @return the status of the operation
 * @retval RTM_OK the operation succeeded and decoded at least one websocket 
 *         frame
 * @retval RTM_WOULD_BLOCK the operation needs more data to process the buffer 
 *         (got partial frames or no frames at all)
 * @retval RTM_ERR_* when something went wrong
 *
 * @see ::rtm_status for details
 */
RTM_API rtm_status rtm_poll(rtm_client_t *rtm);

/**
 * @brief Retrieve the underlying file descriptor so that it can be incorporated
 * into a message loop, like libev or libevent.
 *
 * @param[in] rtm instance of the client
 *
 * @return the system file descriptor associated with the connection
 */
RTM_API int rtm_get_fd(rtm_client_t *rtm);

/**
 * @brief Retrieve the user specific pointer from the client.
 *
 * @param[in] rtm instance of the client.
 *
 * @returns the user context pointer specified when calling ::rtm_init
 */
RTM_API void *rtm_get_user_context(rtm_client_t *rtm);

/**
 * @brief Returns a human-readable string representing the status of operation.
 *
 * @param[in] status of operation.
 *
 * @returns a human-readable description of status.
 */
RTM_API const char *rtm_error_string(rtm_status status);

#ifdef __cplusplus
}
#endif

#endif // CORE_RTM_H__INCLUDED
