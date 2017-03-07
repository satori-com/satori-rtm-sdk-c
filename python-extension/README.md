Run `python setup.py install`, which will both `build` and `install` the C extension. No further compilation is necessary.

Afterwards, within a Python environment, you should be able to run:

```Python
import crtm

connection = crtm.connect("ws://xxx.api.satori.com/", "<appkey>")

crtm.subscribe(connection, "test")
crtm.publish_json(connection, "test", json.dumps({"foo": "bar"))

result = wait_pdus(connection, lambda x: x["action"] == "rtm/subscription/data")

print(result)

crtm.close(connection)
```
