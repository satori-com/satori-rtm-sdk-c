#!/usr/bin/env python

import crtm
import time
import json
import os

def simple_message_test():
    send_message("Hello world")

def json_message_test():
    send_message({"aa": "bb", "cc": "dd"})

def wait_pdus(connection, pred = lambda x: True, timeout = 30):
    start_time = time.time()
    while (time.time() < (start_time + timeout)):
        result = crtm.recv(connection)
        filtered_result = filter(pred, result)
        if filtered_result:
            return filtered_result
        time.sleep(0.100)
    return None

def send_message(message):

    connection = crtm.connect(os.environ.get('ENDPOINT'), os.environ.get('APPKEY'))

    assert connection != None, "Connection failed"

    request_id = crtm.subscribe(connection, "test")
    assert request_id > 0, "Subscription failed"

    result = wait_pdus(connection)

    assert len(result) == 1
    assert result[0]["action"] == "rtm/subscribe/ok"
    assert result[0]["id"] == request_id

    assert crtm.publish_json(connection, "test", json.dumps(message)) > 0, "Publish failed"

    result = wait_pdus(connection, lambda x: x["action"] == "rtm/subscription/data")
    messages = [msg for pdu in result for msg in json.loads(pdu["body"])["messages"]]

    assert messages == [message], "Published message (" + str(message) + ") not found"

    crtm.close(connection)


