tutorial.ino is an example for ESP/Arduino compatible boards, most notably for
the ESP8266.

If you haven't got the Satori library available for your Arduino IDE yet,
you can generate it using

```
$ mkdir build && cd build
$ cmake -DARDUINO_SDK=1 ..
$ make
```

from the SDK's root directory. This will generate a zip-file which you can
import from your Arduino IDE.

Note that Satori requires TLS for the time being. The Arduino Uno with Ethernet
shield is not powerful enough for that; hence, Arduino support is limited to
the ESP-family. It should work with other boards providing the WiFiClient` and
`WiFiClientSecure` classes, too.
