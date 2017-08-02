
main.c contains annotated source code for connecting to RTM, authenticating,
subscribing to a channel and publishing a message.

Building (the SDK will be fetched from github and built automatically in the process):

```
$ mkdir build && cd build
$ cmake .. && cmake --build .
```

Running:

```
$ ./tutorial
```