#!/usr/bin/env python

import json
import shutil
import subprocess
import time

def main():
    with open('credentials.json') as f:
        creds = json.load(f)

    shutil.rmtree('build.quickstart', ignore_errors=True)
    shutil.copytree('tutorial/simple', 'build.quickstart')

    with open('build.quickstart/main.c') as fi:
        with open('build.quickstart/main.c.tmp', 'w') as fo:
            fo.writelines(inject_credentials(creds, l) for l in fi.readlines())
    shutil.move('build.quickstart/main.c.tmp', 'build.quickstart/main.c')

    subprocess.call(['cmake', '.'], cwd='build.quickstart')
    subprocess.call(['cmake', '--build', '.'], cwd='build.quickstart')

    p = subprocess.Popen(['./tutorial'],
        cwd='build.quickstart',
        stdout=subprocess.PIPE,
        bufsize=1)
    try:
        time.sleep(10)
        assert p.returncode == None
    finally:
        p.terminate()

    out, err = p.communicate()

    assert 'Animal is received' in out, out
    assert 'Animal is published' in out, out

    print('Tutorial seems to be working fine')


def inject_credentials(creds, s):
    return s\
        .replace('YOUR_ENDPOINT', creds['endpoint'])\
        .replace('YOUR_APPKEY', creds['appkey'])\
        .replace('YOUR_ROLE', creds['auth_role_name'])\
        .replace('YOUR_SECRET', creds['auth_role_secret_key'])

if __name__ == '__main__':
    main()
