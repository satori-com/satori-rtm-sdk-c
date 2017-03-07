#!/usr/bin/env python
import nose
import json
import os

def main():
    script_dir = os.path.dirname(__file__)

    with open(os.path.join(script_dir, "../../credentials.json"), "r") as creds:
        data = json.load(creds)
        os.environ["APPKEY"] = data["appkey"]
        os.environ["ENDPOINT"] = data["endpoint"].replace("wss://", "ws://")

    if not nose.run(defaultTest=['positive_tests', 'negative_tests']):
        raise RuntimeError("Some tests failed")

if __name__ == '__main__':
    main()
