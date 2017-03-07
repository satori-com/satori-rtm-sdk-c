#!/usr/bin/env python

import crtm
import os

def wrong_url_test():

    connection = crtm.connect("error_url", "")

    assert connection == None, "Connection to wrong url succeeded"

def wrong_appkey_test():

    connection = crtm.connect(os.environ.get('ENDPOINT'), "something_is_wrong_about_this_appkey")

    assert connection == None, "Connection to wrong appkey succeeded"

def publish_to_closed_test():

    connection = crtm.connect(os.environ.get('ENDPOINT'), os.environ.get('APPKEY'))

    assert connection != None, "Connection failed"

    crtm.close(connection)

    assert crtm.subscribe(connection, "test") == None, "Subscribe to closed RTM succeeded"
