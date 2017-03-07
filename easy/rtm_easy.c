#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include <stdint.h>
#include <rtm.h>
#include <rtm_internal.h>
#include "rtm_easy.h"

void rtm_add_pdu(rtm_client_t *rtm, const rtm_pdu_t *pdu) {
    rtm_message_list new_message;
    new_message = (rtm_message_list)malloc(sizeof(struct _rtm_message_list));
    new_message->request_id = pdu->request_id;
    new_message->action = pdu->action ? strdup(pdu->action) : NULL;
    new_message->body = pdu->body ? strdup(pdu->body) : NULL;
    new_message->next = (rtm_message_list)rtm->user;
    rtm->user = new_message;
}

rtm_message_list rtm_easy_next_message(rtm_message_list message) {
    if (message == NULL) return NULL;
    return message->next;
}

void rtm_easy_free(rtm_message_list el) {
    if (el == NULL) return;
    rtm_easy_free(el->next);
    if (el->action) free(el->action);
    if (el->body) free(el->body);
    free(el);
}

int rtm_easy_connect(rtm_client_t *rtm, const char *endpoint, const char *appkey) {
    rtm_status rc = rtm_connect(rtm, endpoint, appkey, &rtm_add_pdu, NULL);
    if (rc == RTM_OK) return 0;
    return -1;
}

int rtm_easy_recv(rtm_client_t *rtm, rtm_message_list *message) {
    rtm->user = NULL;
    int code = rtm_poll(rtm);
    *message = rtm->user;
    return code;
}
