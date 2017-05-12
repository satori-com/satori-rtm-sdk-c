# Swift Playground Examples using iOS-Wrapper
------------------------------------------------

The Swift Playgrounds `SimpleSubscribe` and `FilterSubscibe` included in this repository show how to use the Satori C sdk iOS-Wrapper to subscribe to the Open Data Channels on [Satori](https://www.satori.com/). The purpose of these playgrounds is to demonstrate the simplicity of using the Satori iOS-wrapper to subscribe to open data channels and also to provide you with an interactive way to play with the subscription parameters and Views to understand the subscription concepts better.


## Prerequisites
-----------------


* Xcode 8.0 or greater
* Basic iOS, Swift development knowledge
* Appkeys for [BIG RSS](https://www.satori.com/channels/big-rss) and [Meetup RSVP](https://www.satori.com/channels/Meetup-RSVP) Open Data Channels



## Setup
---------


1. Clone or Download the [satori-rtm-sdk-c](https://github.com/satori-com/satori-rtm-sdk-c) repository.
2. Open `SatoriSwiftExample.xcworkspace` under `ios-wrapper/SwiftExample` in Xcode
3. Select the `SatoriRtmSdkWrapper-Universal` scheme and `Generic iOS Device` in Xcode and run. This builds the iOS-wrapper `SatoriRtmSdkWrapper.framework`
  * **SimpleSubscribe Playground**
    1. Select `SimpleSubscribe` playground from the left project explorer in Xcode. Copy the `Appkey` from [big-rss](https://www.satori.com/channels/big-rss) channel and replace the **AppKeyForBigRss** in ```let appKey = "AppKeyForBigRss"``` with the copied value.
  * **FilterSubscribe Playground**
    1. Select `FilterSubscribe` playground from the left project explorer in Xcode. Copy the `Appkey` from [Meetup-RSVP](https://www.satori.com/channels/Meetup-RSVP) channel and replace the **AppKeyForMeetupRSVP** in ```let appKey = "AppKeyForMeetupRSVP"``` with the copied value.
4. The playground should Automatically Run. If not, click the `Manually Run` button on the bottom debug area panel in Xcode.
5. Click on `Show Assistant Editor` button at the top panel in Xcode to view the visual results of subscription in action.


## Description
---------------

**SimpleSubscribe**


The SimpleSubscribe Playground subscribes to the [Meetup-RSVP](https://www.satori.com/channels/Meetup-RSVP) open data channel. It parses the subscription data and displays the RSS feed `Title` and `Published On` field values in a auto-scrolling read-only textview in the Xcode Assistant Editor window.



**FilterSubscribe**


The FilterSubscribe Playground subscribes to the [big-rss](https://www.satori.com/channels/big-rss) open data channel. The playground applies a View(formerly Filter) to the channel to only subscribe for the events that are happening in the USA. It parses the subscription data and displays a location pin for each of the meetups on the US map as they occur in real time.