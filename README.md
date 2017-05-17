C SDK for Satori RTM
====================

This C SDK is a lightweight SDK:
 * It has no external dependencies, in particular it does not require a JSON library
 * It does not lock you into using any threading or event loop framework, but is ready to be used in any of those
 * Does not allocate memory dynamically. All message processing is done in-place
 * Has less features than other Satori RTM SDKs, e.g. it has no auto-reconnection
 * Is likely to be used as a base for building higher-level SDKs (see ios-wrapper for example)

Build
=====

For desktop/server
------------------

The build system is using [cmake](https://cmake.org/).

Supported compilers:
 * Microsoft Visual Studio 2015 or newer
 * gcc-4.9 or newer
 * clang-3.6 or newer

To build, just execute:
```sh
$ mkdir build && cd build
$ cmake ..
$ cmake --build .
```

To build with tests, execute:
```sh
$ cmake .. -Dtest=1
$ cmake --build .
```

To run the unit tests, first you need to create a credentials.json file:

```sh
$ cat credentials.json
{
  "endpoint": "wss://<SATORI_HOST>/",
  "appkey": "my_appkey",
  "auth_role_name": "ROLE NAME"
  "auth_role_secret_key": "ROLE SECRET"
  "auth_restricted_channel": "RESTRICTED CHANNEL"
}
```

* `endpoint` is your customer-specific DNS name for RTM access.
* `appkey` is your application key.
* `auth_role_name` is a role name that permits publishing / subscribing to `auth_restricted_channel`. Must be not `default`.
* `auth_role_secret_key` is a secret key for `auth_role_name`.
* `auth_restricted_channel` is a channel with subscribe and publish access for `auth_role_name` role only.

You must use [DevPortal](https://developer.satori.com/) to create role and set channel permissions.


After that, execute:
```sh
$ ./core/test/rtm_unit_tests
```

TLS support
-----------

The SDK can take advantage of either OpenSSL, GNUTLS or Apple SSL API for supporting secure (wss://) connections.
Pass one of "-DUSE_OPENSSL=ON", "-DUSE_GNUTLS=ON" or "-DUSE_APPLE_SSL=ON" respectively to CMake.

If no flags are passed, CMake enables Apple SSL for Mac or OpenSSL for others.

## iOS wrapper

The SatoriRtmSdkWrapper framework for iOS enables you to easily integrate your iOS apps with Satori RTM. Using the framework, you can publish and subscribe messages to RTM. There are multiple ways for installing the SatoriRtmSdkWrapper framework in your own project.

### Installation with CocoaPods

The SatoriRtmSdkWrapper is available as a [CocoaPod](http://cocoapods.org). Cocoapod is a dependency manager for iOS, which automates and simplifies the process of using 3rd-party frameworks like SatoriRtmSdkWrapper in your projects. Make sure cocoapods is installed. Then create a podfile for your project if it doesn't already exist. To install the SDK:

1. Open your Podfile and add the following dependency in the `target "<your_app_target>" do` section:
```sh
use_frameworks!
pod 'SatoriRtmSdkWrapper', :git => "https://github.com/satori-com/satori-rtm-sdk-c.git"
```
2. Save your Podfile.
3. Run `pod install` from command line.

You've now installed the SatoriRtmSdkWrapper framework. Refer to *Framework API usage* section to get started.

### Manual installation using Source code

Create a local repository by cloning the satori-rtm-sdk-c to your chosen location. Then,

#### Step 1: Build framework

There are two options to build the RTM framework for iOS:

**Option 1** - *Build directly from command-line*

```sh
$ cd ios-wrapper/SatoriRtmSdkWrapper
$ xcodebuild -project SatoriRtmSdkWrapper.xcodeproj -scheme SatoriRtmSdkWrapper-Universal -config <config-name> # where <config-name> can be Debug or Release. Default is Debug if -config option is not specified.
```
**Option 2** - *Build in Xcode IDE*
```sh
$ open SatoriRtmSdkWrapper.xcodeproj
$ # Select SatoriRtmSdkWrapper-Universal target and build.
```
The SatoriRtmSdkWrapper.framework will be built under ios-framework/build directory.

#### Step 2: Add framework to your project

Once you build the framework, open your app's Xcode project and drag-and-drop the framework under "Embedded Binaries" section under the app's target. Choose "Copy items if needed" and "Create groups" in the dialog box.

### Framework API usage

The SatoriRtmSdkWrapper.framework provides you with both Objective-C and C APIs to integrate within your app. Use ```#import <SatoriRtmSdkWrapper/SatoriRtmSdkWrapper.h>``` in your application class to make use of these APIs. The Objective-C specific APIs are located in ```SatoriRtmConnection.h``` and C APIs can be found in ```rtm.h```

##### Objective-C Sample Code

```Objective-C

// create a new rtm instance with url and appKey
SatoriRtmConnection *rtm = [[SatoriRtmConnection alloc] initWithUrl:"url" andAppkey:"appkey"];

// connect to rtm and provide pdu data handler block
rtm_status status = [rtm connectWithPduHandler:^(SatoriPdu * _Nonnull pdu) {
        //Use pdu
    }];

// subscribe to a channel
unsigned int reqId;
[rtm subscribe:@"channel-name" andRequestId:&reqId];

// publish a string or json to a channel
unsigned int reqId;
[rtm publishString:@"Hello world" toChannel:@"channel-name" andRequestId:&reqId];
[rtm publishJson:@"{\"key\":\"value\"}" toChannel:@"channel-name" andRequestId:&reqId];

// Enable or disable verbose logging of all incoming and outgoing PDUs
rtm.enableVerboseLogging = YES;
rtm.enableVerboseLogging = NO;

// Use wait or waitWithTimeout methods to block until at least one data message gets processed
[rtm wait];
[rtm waitWithTimeout:15];

// For non-blocking wait, use poll
while([rtm poll] >= 0) { sleep(1); }

// Make sure to disconnect when rtm connection is no longer needed
[rtm disconnect];

```


For Windows (Visual Studio)
---------------------------

Assuming Visual Studio and cmake are installed, open Developer Command Prompt for Visual Studio.

```sh
C:\satori-rtm-sdk-c> mkdir vsprj
C:\satori-rtm-sdk-c> cd vsprj
C:\satori-rtm-sdk-c\vsprj> cmake -DBUILD_SHARED_LIBS=ON -G "Visual Studio 14 2015" ..
C:\satori-rtm-sdk-c\vsprj> msbuild satori-sdk-c.sln
```

Adjust the generator name from "Visual Studio 14 2015" to another if necessary.

For TLS support only "-DUSE_OPENSSL=ON" is supported at this time.

To compile with OpenSSL you need to:
1. Download and install the appropriate distribution from https://slproweb.com/products/Win32OpenSSL.html
2. Update your project properties to add additional include folders (pointing to the above install location)
3. Update project properties to refer to library path of the above installation 
4. Add OpenSSL library files to your linker input libraries. The names for those
   depend on OpenSSL version: libssl.lib and libcrypto.lib for 1.1.x and
   libeay.lib and ssleay.lib for 1.0.x. There also could be some variations in naming
   like ssleay32MD.lib depending on the OpenSSL distribution.


Additionally, WinSock subsystem must be initialized prior to connecting to RTM.

```C
    #include <WinSock2.h>
    #include <Windows.h>
    #include <WS2tcpip.h>

    ...

    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD(2, 2);
    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        fprintf(stderr, "WSAStartup failed with code %d", err);
    }
```

Usage
=====
```C
rtm_client_t *rtm = (rtm_client_t*) malloc (rtm_client_size);
rtm_connect(rtm, "wss://myorg.api.satori.com/", "<APPKEY>", rtm_default_pdu_handler, NULL);
rtm_subscribe(rtm, "channel_a", NULL);
rtm_publish_string(rtm, "channel_a", "Hello, world", NULL);
rtm_publish_json(rtm, "channel_a", "{\"key\":\"value\", \"k2\":123}", NULL);
while (rtm_poll(rtm)>=0) { sleep(1); }
rtm_close(rtm);
free(rtm);
```

`rtm_poll(rtm)` can be substitued for `rtm_wait(rtm)` to avoid the sleep when there is nothing better to do.
```while (rtm_wait(rtm)>=0) {}```

All channel data events go to the `message_handler` specified in the call to `rtm_connect`, other notifications, such as acknowledgements go to the `event_handler`. The default handlers simply print out to stdout.

In order to use RTM receipts/acknowledgements, simply provide the last argument to the `subscribe`/`unsubscribe`/`publish` functions instead of `NULL`. This argument is of type `unsigned int` and will be generated by the SDK on every function call. The generated id will be stored in the provided pointer and will eventually show in one of the `event_handler` callbacks when the acknowledgement arrives on the wire. When passing `NULL` no receipts will be generated.

You can use `rtm_get_fd(rtm)` to get the underlying file descriptor in order to connect to a message loop / select / poll.
In such a case, simply call `rtm_poll(rtm)` whenever there is data that can be read from the socket.
`rtm_poll()` never blocks.
`rtm_wait()` is a blocking alternative to `rtm_poll()` which blocks until at least one data message gets processed. Use it if you have nothing better to do.
`rtm_publish_*()` may block if the network blocks.
`rtm_connect()` will block until the connection handshake is complete.
You can set the global `rtm_connect_timeout` to the maximum number of seconds to wait for the connection handshake to complete.

A global error handler can be set by setting `rtm_error_logger` to any function that takes a `const char* msg`. The default one prints errors to stderr.

Verbose logging of all incoming and outcoming PDUs
==================================================

You can enable dumping of all PDUs to stderr either from your code::

  rtm_connect(rtm, ...);
  rtm_enable_verbose_logging(rtm);

or by setting DEBUG_SATORI_SDK environment variable prior to running your application::

  export DEBUG_SATORI_SDK=1
  ./my_program


Missing functionality
=====================
- Handling of network errors is left to the user
- Providing access to the `position` in RTM messages (and during subscription)