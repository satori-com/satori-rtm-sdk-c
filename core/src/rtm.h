/**
 * @file
 * @brief RTM CORE SDK documentation.
 *
 * @details
 *
 * This Core SDK is a very low level to the RTM service.
 *
 * @code{.c}
 *
 * // allocate some memory to store the client
 * char client[rtm_client_size];
 * ...
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
#ifndef USE_TLS
#define USE_TLS
#endif
#endif

/**
 * @brief maximum size of a channel name
 */
#define RTM_MAX_CHANNEL_SIZE (256)

/**
 * @brief maximum size of a message
 */
#define RTM_MAX_MESSAGE_SIZE (65536)

/**
 * @brief RTM path
 */
#define RTM_PATH ("/v2")


/**
 * @brief maximum size of the endpoint parameter
 */
#define RTM_MAX_ENDPOINT_SIZE (256)

/**
 * @brief maximum size of the appkey parameter
 */
#define RTM_MAX_APPKEY_SIZE (32)

/**
 * @brief maximum size of the role name parameter
 */
#define RTM_MAX_ROLE_NAME_SIZE (512)

/**
 * @brief expected size of the authentication hash parameter in bytes
 */
#define RTM_AUTHENTICATION_HASH_SIZE (24)

/**
 * @brief Structure containing information about the received pdu.
 */
typedef struct _rtm_pdu {
    const char *action;
    const char *body;
    unsigned request_id;
} rtm_pdu_t;

/**
 * @brief opaque rtm client structure
 */
typedef struct _rtm_client rtm_client_t;

/**
 * @brief callback function invoked when client receives messages from RTM.
 *
 * When ::rtm_connect is called, a pointer to a user defined structure can be 
 * set.
 * You can get this value from @p rtm in the context of this callback by calling
 * ::rtm_get_user_context:
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
 * @brief callback function invoked when client receives PDU from RTM.
 *
 * When ::rtm_connect is called, a pointer to a user defined structure can be
 * set. You can get this value from @p rtm in the context of this callback by 
 * calling ::rtm_get_user_context:
 *
 * @code{.c}
 * void my_pdu_callback(rtm_client_t *rtm, const rtm_pdu_t *pdu) {
 *    my_context *context = (my_context *) rtm_get_user(rtm);
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
 * @brief global error logging function
 */
typedef void(*rtm_error_logger_t)(const char *message);

/**
 * @brief type used internally to report errors.
 *
 * The values can be used to diagnose errors that happen while interacting with 
 * c core.
 */
typedef enum {
    RTM_OK = 0,             /*!< No error.                                    */
    RTM_WOULD_BLOCK,        /*!< The operation would be a blocking IO
                                 operation                                    */
    RTM_ERR_BEGIN = -100,
    RTM_ERR_PARAM,          /*!< One of the parameters passed to the function
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
    RTM_ERR_TIMEOUT,
    RTM_ERR_END
} rtm_status;

/**
 * @brief global connection timeout in seconds. The default value is @c 10
 */
RTM_API extern time_t rtm_connect_timeout;

/**
 * @brief size of ::rtm_client_t in bytes
 */
RTM_API extern const size_t rtm_client_size;

/**
 * @brief global pointer to the rtm_error_logger() function. The default value
 * is @c ::rtm_default_error_logger
 */
extern void(*rtm_error_logger)(const char *message);

/**
 * @brief global pointer to the rtm_text_frame_handler() function. The default value is
 * @c ::rtm_default_pdu_handler
 */
extern void(*rtm_text_frame_handler)(rtm_client_t *rtm, char *message,
    size_t message_len);

/**
 * @brief default error handler.
 * This handler sends all messages to stderr.
 * @param[in] message the message to log as a zero terminated string.
 */
void rtm_default_error_logger(const char *message);

/**
 * @brief default message handler prints all messages to stdout
 *
 * @param[in] rtm instance of the client
 * @param[in] channel name of the channel
 * @param[in] message message to output
 */
void rtm_default_message_handler(rtm_client_t *rtm, const char *channel,
                                 const char *message);

/**
 * @brief default PDU handler prints all PDUs to stdout
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
 * @brief Enable logging of incoming and outcoming PDUs
 *
 * @param[in] rtm instance of the client
 *
 */
RTM_API void rtm_enable_verbose_logging(rtm_client_t *rtm);

/**
 * @brief Disable logging of incoming and outcoming PDUs
 *
 * @param[in] rtm instance of the client
 *
 */
RTM_API void rtm_disable_verbose_logging(rtm_client_t *rtm);

/**
   @brief close an RTM connection.

 * This releases any underlying resources of the RTM object.
 * Do not use the object after calling this function
 * It is safe to call this function from pdu handlers to terminate 
 * the connection on e.g., errors
 *
 * @param[in] rtm instance of the client
 *
 */
RTM_API void rtm_close(rtm_client_t *rtm);

RTM_API rtm_status rtm_handshake(rtm_client_t *rtm,
                         const char *role, unsigned *ack_id);

RTM_API rtm_status rtm_authenticate(rtm_client_t *rtm,
                            const char *hash, unsigned *ack_id);

#if defined(USE_OPENSSL)
void rtm_calculate_md5_hmac(char const *role_secret, char const *nonce, unsigned char *output_16bytes);
#else
#define rtm_calculate_md5_hmac(...) _Pragma ("GCC error \"This function is only available when compiling with OpenSSL\"")
#endif

/**
 * @brief publish a well formed json string
 *
 * Publish a well formed JSON message to RTM.
 *
 * If @p ack_id is not null, its value will contain the ID of the message.
 * Later on, when you receive a confirmation, it will make it possible to check 
 * the status.
 *
 * @param[in] rtm instance of the client
 * @param[in] channel name of the channel
 * @param[in] json message to output
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
 * @brief Publish a raw string
 *
 * and request the operation to be acknowledged by the server. Upon 
 * acknowledgement the
 *
 * @param[in] rtm instance of the client
 * @param[in] channel name of the channel
 * @param[in] string the message to send. @p string must be @c NULL terminated 
 *            (i.e. a c string.)
 * @param[out] ack_id (\e optional) the id of the message sent.
 *
 * @note @p will be escaped before transmission.
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
 * @brief subscribe to a channel
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
 * @brief subscribe to a channel with specifying PDU `body` field
 *
 * @param[in] rtm instance of the client
 * @param[in] body of pdu for subscribe request
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
 * @brief unsubscribe from a channel
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

RTM_API void rtm_parse_pdu(char *json, rtm_pdu_t *pdu_out);
RTM_API void rtm_parse_subscription_data(rtm_client_t *rtm, const rtm_pdu_t* pdu,
    char* const buf, size_t size, rtm_message_handler_t *handler);
RTM_API rtm_status rtm_read(rtm_client_t *rtm, const char *channel, unsigned *ack_id);
RTM_API rtm_status rtm_read_with_body(rtm_client_t *rtm, const char *body, unsigned *ack_id);
RTM_API rtm_status rtm_write_string(rtm_client_t *rtm, const char *key, const char *string,
    unsigned *ack_id);
RTM_API rtm_status rtm_write_json(rtm_client_t *rtm, const char *key, const char *json,
    unsigned *ack_id);
RTM_API rtm_status rtm_delete(rtm_client_t *rtm, const char *key, unsigned *ack_id);

RTM_API rtm_status rtm_search(rtm_client_t *rtm, const char *prefix, unsigned *ack_id);
RTM_API rtm_status rtm_send_pdu(rtm_client_t *rtm, const char *json);

/**
 * @brief wait for the underlying file descriptor to be ready.
 *
 * This method will return after at least one message is processed or an error 
 * occurs,
 * So it can be used in a tight loop without consuming CPU resources when there 
 * is no data to read
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
 * @brief wait for the underlying file descriptor to be ready.
 *
 * Like rtm_wait, but with a timeout in seconds
 * 
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
 * @brief poll the underlying file descriptor for any PDUs and execute the 
 * callbacks as needed
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
 * @brief retrieve the underlying file descriptor so that it can be incorporated 
 * into a message loop, like libev or libevent
 *
 * @param[in] rtm instance of the client
 *
 * @return the system file descriptor associated with the connection
 */
RTM_API int rtm_get_fd(rtm_client_t *rtm);

/**
 * @brief retrieve the user specific pointer from the client
 *
 * @param[in] rtm instance of the client
 *
 * @returns the user context pointer specified when calling ::rtm_connect
 */
RTM_API void *rtm_get_user_context(rtm_client_t *rtm);

RTM_API void rtm_b64encode_16bytes(char const *input, char *output);

#ifdef __cplusplus
}
#endif

#endif // CORE_RTM_H__INCLUDED
