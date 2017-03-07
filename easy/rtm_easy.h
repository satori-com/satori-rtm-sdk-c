/*
 rtmclient
 
 Created by Boaz Sedan on 3/15/16.
 */

#ifndef rtm_easy_h
#define rtm_easy_h

#ifdef __cplusplus
extern "C" {
#endif

    /**************/
    /* Data types */

    typedef struct _rtm_message_list {
        unsigned request_id;
        char *action;
        char *body;
        struct _rtm_message_list *next;
    } *rtm_message_list;

    /* connect to RTM, provide a full URL
     * rtm - RTM structure to use
     * endpoint - "ws://xxx.api.satori.com/
     * appkey - Application key from DevPortal
     * returns 0 on success
     */
    extern int rtm_easy_connect(rtm_client_t *rtm, const char *endpoint, const char *appkey);
    /* set RTM callback
     * rtm - RTM structure to use
     * data_handler - callback for channel data
     * event_handler - callback for non data events
     * user - an opaque user specified data associated with this RTM object
     */

    extern int rtm_easy_recv(rtm_client_t *rtm, rtm_message_list *message);

    extern void rtm_easy_free(rtm_message_list message);

    extern rtm_message_list rtm_easy_next_message(rtm_message_list message);
    
#ifdef __cplusplus
}
#endif


#endif /* rtm_easy_h */
