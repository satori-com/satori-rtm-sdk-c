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
 * rtm_client_t *rtm = (rtm_client_t *)malloc(rtm_client_size);
 * // connect to RTM
 * int rc = rtm_connect(rtm, endpoint, appkey, rtm_default_pdu_handler, 0);
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

#if defined(USE_APPLE_SSL) || defined(USE_OPENSSL) || defined(USE_GNUTLS)
#define USE_TLS
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
 * @brief Structure representing received PDU JSON object.
 */
typedef struct _rtm_pdu {
    const char *action; /*!<  RTM action string. */
    const char *body; /*!< Data associated with a given action. */
    unsigned request_id; /*!< Identifier to match server replies to the client requests. */
} rtm_pdu_t;

/**
 * @brief Opaque rtm client structure.
 */
typedef struct _rtm_client rtm_client_t;

/**
 * @brief Type of callback function invoked when client receives messages from RTM.
 *
 * @note when ::rtm_connect is called, a pointer to a user defined structure
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
 * @see ::rtm_connect
 */
typedef void(rtm_message_handler_t)(rtm_client_t *rtm, const char *subscription_id,
             const char *message);

/**
 * @brief Type of callback function invoked when client receives PDU from RTM.
 *
 * @note when ::rtm_connect is called, a pointer to a user defined structure can be
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
 * @see ::rtm_connect
 * @see ::rtm_get_user_context
 *
 */
typedef void(rtm_pdu_handler_t)(rtm_client_t *rtm, const rtm_pdu_t *pdu);

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
    RTM_OK = 0,             /*!< No error.                                    */
    RTM_WOULD_BLOCK,        /*!< The operation would be a blocking IO
                                 operation                                    */
    RTM_ERR_PARAM = -100,   /*!< One of the parameters passed to the function
                                 is incorrect                                 */
    RTM_ERR_PARAM_INVALID,  /*!< A parameter of the function is invalid       */
    RTM_ERR_CONNECT,        /*!< The client could not connect to RTM          */
    RTM_ERR_NETWORK,        /*!< An unexpected network error occurred         */
    RTM_ERR_CLOSED,         /*!< The connection is closed                     */
    RTM_ERR_READ,           /*!< An error occurred while receiving data from
                                 RTM                                          */
    RTM_ERR_WRITE,          /*!< An error occurred while sending data to RTM  */
    RTM_ERR_PROTOCOL,       /*!< An error occurred in the protocol layer      */
    RTM_ERR_NO_TLS,         /*!< The call to ::rtm_connect mentioned a TLS
                                 endpoint, but the SDK was not built with TLS
                                 support                                      */
    RTM_ERR_TLS,            /*!< An unexpected error happened in the TLS
                                 layer                                        */
    RTM_ERR_TIMEOUT         /*!< The operation timed out                      */
} rtm_status;

/**
 * @brief Global connection timeout in seconds. The default value is @c 10.
 */
RTM_API extern time_t rtm_connect_timeout;

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
 * @brief Initialize an instance of rtm_client_t and connects to RTM.
 *
 * @param[in] rtm instance of the client
 * @param[in] endpoint endpoint for the RTM Service.
 * @param[in] appkey application key to the RTM Service.
 * @param[in] pdu_handler the callback for non data PDUs
 * @param[in] user_context an opaque user specified data associated with this 
 *            RTM object
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
                       const char *appkey,
                       rtm_pdu_handler_t *pdu_handler,
                       void *user_context);

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
RTM_API void rtm_parse_subscription_data(rtm_client_t *rtm, const rtm_pdu_t* pdu,
    char* const buf, size_t size, rtm_message_handler_t *handler);

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
 * @returns the user context pointer specified when calling ::rtm_connect
 */
RTM_API void *rtm_get_user_context(rtm_client_t *rtm);

#ifdef __cplusplus
}
#endif

#endif // CORE_RTM_H__INCLUDED
