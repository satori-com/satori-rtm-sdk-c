#!/usr/bin/env python
# encoding: utf-8

import json
import os
import re
import signal
import shutil
import subprocess
import threading
import time


TUTORIALS = {
    # key is directory name, value is an iterable of regular expressions that must
    # each match against the command's output
    "simple": {"Animal is received", "Animal is published"},
    "libuv":  {"Animal is received", "Animal with ID [0-9]+ is published"},
    "boost_asio": {"Sent out an animal", "Received animal"},
}


def main():
    for tutorial in TUTORIALS.items():
        test(*tutorial)

def kill_after(process, seconds=10):
    time.sleep(seconds)
    try:
        if process.poll() is None:
            process.terminate()
    except:
        pass

def test(tutorial_name, test_strings):
    print
    print "Testing if tutorial %s works" % tutorial_name
    print

    with open('credentials.json') as f:
        creds = json.load(f)

    shutil.rmtree('build.quickstart', ignore_errors=True)
    shutil.copytree('tutorial/%s' % (tutorial_name,), 'build.quickstart')

    for file_name in os.listdir("build.quickstart"):
        if "main" in file_name:
            file_name = os.path.join("build.quickstart", file_name)
            with open(file_name) as fi:
                with open("%s.tmp" % file_name, 'w') as fo:
                    fo.writelines(inject_credentials(creds, l) for l in fi.readlines())
            shutil.move("%s.tmp" % file_name, file_name)

    subprocess.check_call(['cmake', '.'], cwd='build.quickstart')
    subprocess.check_call(['cmake', '--build', '.'], cwd='build.quickstart')

    print

    p = subprocess.Popen(['./tutorial'],
        cwd='build.quickstart',
        stdout=subprocess.PIPE,
        bufsize=1)

    kill_thread = threading.Thread(target=kill_after, args=(p, 10))
    kill_thread.daemon = True
    kill_thread.start()

    out, err = p.communicate()

    # Should either have terminated on its own or due to us terminating the
    # process
    assert p.returncode in (-signal.SIGTERM, 0)

    for test_string in test_strings:
        if not re.search(test_string, out):
            print "Test string '%s' did not match against output:\n%s" % (test_string, out)
            raise AssertionError()

    print
    print "Tutorial %s seems to be working fine" % tutorial_name


def inject_credentials(creds, s):
    return s\
        .replace('YOUR_ENDPOINT', creds['endpoint'])\
        .replace('YOUR_APPKEY', creds['appkey'])\
        .replace('YOUR_ROLE', creds['auth_role_name'])\
        .replace('YOUR_SECRET', creds['auth_role_secret_key'])

if __name__ == '__main__':
    main()
