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

#include <rtm_config.h>

#ifdef _WIN32
  #if !defined(__WINDOWS__)
    #define __WINDOWS__
  #endif
  #include <Winsock2.h>
  #include <BaseTsd.h>
  typedef SSIZE_T ssize_t;
#endif

#if defined(RTM_USE_GNUTLS)

#include <gnutls/gnutls.h>

#elif defined(RTM_USE_OPENSSL)

#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#elif defined(RTM_USE_APPLE_SSL)

#include <Security/Security.h>
#include <Security/SecureTransport.h>

#endif


#if defined(rtm_core_sdk_EXPORTS) && defined(_WIN32)
#define RTM_API __declspec(dllexport)
#elif defined(_WIN32) && !defined(RTM_BUILD_STATIC)
#define RTM_API __declspec(dllimport)
#else
#define RTM_API
#endif

#if RTM_TEST_ENV
#define RTM_TEST_API RTM_API
#else
#define RTM_TEST_API
#endif

#define _RTM_SCRATCH_BUFFER_SIZE (256)
#define _RTM_WS_PRE_BUFFER 16

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
    };
} rtm_pdu_t;

/**
 * @brief Opaque rtm client structure.
 */
typedef struct rtm_client rtm_client_t;

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
 * @brief Error logging function.
 */
typedef void(rtm_error_logger_t)(const char *message);

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
    RTM_ERR_OOM = -100,           /*!< Insufficient memory for this operation        */
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
 * @brief Default size of ::rtm_client_t in bytes.
 */
RTM_API extern const size_t rtm_client_size;

/**
 * @brief Set the error logger used by the RTM structure. The default value
 * is @c ::rtm_default_error_logger.
 */
RTM_API void rtm_set_error_logger(rtm_client_t *rtm, rtm_error_logger_t *error_logger);


/**
 * @brief malloc() like function for use with RTM.
 *
 * @param[in] rtm instance of the client
 * @param[in] size amount of memory to be allocated
 * @return A pointer to the newly allocated memory, or NULL if the allocation
 *         failed
 *
 * @see ::rtm_set_allocator
 * @see ::rtm_system_malloc
 * @see ::rtm_null_malloc
 */
typedef void *(rtm_malloc_fn_t)(rtm_client_t *rtm, size_t size);

/**
 * @brief free() like function for use with RTM.
 *
 * @param[in] rtm instance of the client
 * @param[in] ptr pointer to memory to be released
 *
 * @see ::rtm_set_allocator
 * @see ::rtm_system_free
 * @see ::rtm_null_free
 */
typedef void (rtm_free_fn_t)(rtm_client_t *rtm, void *ptr);

/**
 * @brief malloc() implementation using the system's malloc()
 */
RTM_API void *rtm_system_malloc(rtm_client_t *rtm, size_t size);

/**
 * @brief free() implementation using the system's free()
 */
RTM_API void rtm_system_free(rtm_client_t *rtm, void *mem);

/**
 * @brief malloc() implementation that always fails gracefully
 *
 * This function always returns NULL. Use it if you would like to skip over
 * frames that are too large to handle.
 */
RTM_API void *rtm_null_malloc(rtm_client_t *rtm, size_t size);

/**
 * @brief free() implementation that does nothing
 */
RTM_API void rtm_null_free(rtm_client_t *rtm, void *mem);

/**
 * @brief Set the allocator used by the RTM structure.
 *
 * By default, RTM does not ever allocate any memory and fails hard by closing
 * the connection if it would need to.
 *
 * When the SDK runs out of memory, it invokes the allocator function. If this
 * function returns non-NULL, it assumes that it was given a pointer to memory
 * of at least the requested size and uses that memory to perform the requested
 * action. Once the action is completed, the free() function is called and the
 * memory is released. If the allocator returns NULL, the SDK tries to
 * gracefully handle the error condition. It will skip over frames that are too
 * large to handle, and over fragmented frames that would become too large
 * after reassembly. To fail hard, close the connection from the malloc()
 * function.
 *
 * The SDK provides default functions for convenience.
 *
 * @see ::rtm_system_free
 * @see ::rtm_null_free
 * @see ::rtm_system_malloc
 * @see ::rtm_null_malloc
 */
RTM_API void rtm_set_allocator(rtm_client_t *rtm, rtm_malloc_fn_t *malloc_ptr, rtm_free_fn_t *free_ptr);

/**
 * @brief Default error handler.
 *
 * This handler sends all messages to stderr.
 *
 * @param[in] message to log as a zero terminated string.
 */
RTM_API void rtm_default_error_logger(const char *message);

/**
 * @brief Default message handler prints all messages to stdout.
 *
 * @param[in] rtm instance of the client
 * @param[in] channel name of the channel
 * @param[in] message message to output
 */
RTM_API void rtm_default_message_handler(rtm_client_t *rtm, const char *channel,
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
 * @param[in] memory a buffer of size rtm_client_size
 * @param[in] pdu_handler the callback for all PDUs
 * @param[in] user_context an opaque user specified data associated with this 
 *            RTM object
 *
 *
 * @return initialized rtm_client_t object
 *
 * @see ::rtm_init_ex
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
 * @brief Calculate the size requirements for a RTM client
 *
 * @param[in] buffer_size Total number of bytes for buffers
 * @return size of the rtm_client_t structure
 */
#define RTM_CLIENT_SIZE_WITH_BUFFERS(buffer_size) (sizeof(struct _rtm_client_priv) + _RTM_WS_PRE_BUFFER + 2*buffer_size)

/**
 * @brief Preferred size of a RTM client
 */
#define RTM_CLIENT_SIZE (RTM_CLIENT_SIZE_WITH_BUFFERS(RTM_MAX_MESSAGE_SIZE))

/**
 * @brief Initialize an instance of rtm_client_t with a custom buffer size
 *
 * @param[in] memory a buffer of at least rtm_client_min_size bytes
 * @param[in] memory_size The allocation size of memory
 * @param[in] pdu_handler the callback for all PDUs
 * @param[in] user_context an opaque user specified data associated with this
 *            RTM object
 *
 *
 * @return initialized rtm_client_t object
 *
 * @see ::RTM_CLIENT_SIZE
 * @see ::rtm_init
 * @see ::rtm_close
 * @see ::rtm_get_user_context
 *
 *
 */
RTM_API rtm_client_t *rtm_init_ex(
  void *memory,
  size_t memory_size,
  rtm_pdu_handler_t *pdu_handler,
  void *user_context);

/**
 * @brief Connects to RTM
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
 * @brief Connects to RTM via an https proxy
 *
 * @param[in] rtm instance of the client
 * @param[in] endpoint endpoint for the RTM Service.
 * @param[in] appkey application key to the RTM Service.
 * @param[in] proxy_endpoint
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
RTM_API rtm_status rtm_connect_via_https_proxy(
    rtm_client_t *rtm,
    char const *endpoint,
    char const *appkey,
    char const *proxy_endpoint);

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
 * @retval RTM_ERR_* an error occurred
 */
RTM_API rtm_status rtm_parse_pdu(char *message, rtm_pdu_t *pdu);

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

/**
 * Internal representation of the RTM client's state
 *
 * This structure is private and not part of the public API.
 */
struct _rtm_client_priv {
  //!< @privatesection

  void *user; /*!< User specified context pointer. @see ::rtm_get_user_context. */
  int fd; /*!< File descriptor for the socket used by the SDK */

  /**
   * Total number of bytes in the current input buffer currently used for
   * storing a partial frame reconstructed from a number of
   * fragmented/continuation frames
   */
  size_t fragmented_message_length;

  /**
   * Total number of bytes in the current input buffer currently used for
   * storing unprocessed input
   */
  size_t input_length;

  /**
   * Number of bytes to be skipped when reading incoming data. Incoming bytes
   * are normaly stored in the input buffer. If this variable is non-zero, then
   * the next that-many bytes are instead discarded.
   */
  size_t skip_next_n_input_bytes;

  unsigned is_closed: 1; /*!< Whether the SDK is currently connected */
  unsigned is_used: 1; /*!< Whether there is a pending operation in the SDK */
  unsigned is_verbose: 1; /*!< Whether to verbosely log debug information */

  /**
   * Whether the current fragmented message should be skipped instead of
   * processing it.
   *
   * The SDK normally reassembles messages from fragments. If the user knows
   * that there isn't enough memory available to store the whole message,
   * then they can decide to skip a message completely.
   **/
  unsigned skip_current_fragmented_message: 1;

  unsigned last_request_id; /*!< The largest request ID used so far */
  unsigned last_ping_ts; /*!< Timestamp of the last websocket ping */
  time_t ws_ping_interval; /*!< How often to send websocket pings */

  unsigned is_secure: 1; /*!< Whether this connection uses TLS */
  #if defined(RTM_USE_GNUTLS)
    gnutls_session_t session;
  #elif defined(RTM_USE_OPENSSL)
    SSL_CTX *ssl_context;
    SSL *ssl_connection;
  #elif defined(RTM_USE_APPLE_SSL)
    SSLContextRef sslContext;
  #endif

  unsigned connect_timeout; /*!< Number of seconds to wait for connect() to succeed */
  rtm_pdu_handler_t *handle_pdu; /*!< PDU handler function pointer */
  rtm_raw_pdu_handler_t *handle_raw_pdu; /*!< Raw PDU handler function pointer */

  rtm_error_logger_t *error_logger; /*!< Error logger function pointer */
  rtm_malloc_fn_t *malloc_fn; /*!< malloc() function pointer */
  rtm_free_fn_t *free_fn; /*!< free() function pointer */

  /**
   * The scratch buffer is used for format error messages
   */
  char scratch_buffer[_RTM_SCRATCH_BUFFER_SIZE];

  // The buffers are padded so we are always guaranteed to have
  // enough bytes to pre pad any buffer with websocket framing

  /**
   * The input buffer is used to store incoming data until it is processed.
   *
   * It's memory layout is as follows:
   *
   * input_buffer + 0:
   *   The payload of a fragmented message which is yet to be received
   *   completely
   *
   * input_buffer + fragmented_message_length:
   *   Any (partially) received frames that have not been processed yet
   *
   * input_buffer + fragmented_message_length + input_length:
   *   Unused buffer space
   *
   * input_buffer + input_buffer_size:
   *   End of the input buffer
   *
   * If the memory in the input buffer does not suffice to store a message,
   * the SDK might use the dynamic_input_buffer instead. It will take care
   * of allocating memory & moving the data around.
   *
   * @see ::rtm_set_allocator
   *
   */
  char *input_buffer;
  size_t input_buffer_size; /*!< Input buffer size */

  /**
   * The output buffer is used to construct outgoing data
   *
   * Any messages constructed within this buffer must be offset by
   * _RTM_WS_PRE_BUFFER bytes, because the function used to send websocket
   * frames will prepend a websocket header to messages which can be up to
   * _RTM_WS_PRE_BUFFER bytes long.
   *
   * If the buffer size is not enough to store a message, the SDK might
   * dynamically allocate space instead.
   *
   * @see ::rtm_set_allocator
   */
  size_t output_buffer_size;
  char *output_buffer;

  size_t dynamic_input_buffer_size; /*!< Dynamic input buffer. @see input_buffer */
  char *dynamic_input_buffer; /*!< Size of the dynamic input buffer */
};

struct rtm_client {
  struct _rtm_client_priv priv;
};


#ifdef __cplusplus
}
#endif

#endif // CORE_RTM_H__INCLUDED
