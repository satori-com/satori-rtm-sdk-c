import MapKit
import PlaygroundSupport
import SatoriRtmSdkWrapper
//: ![Satori](SatoriLogo.jpg)
//: ## Using Filters with Open Data Channel
/*:
 [Meetup-RSVP Channel]: https://www.satori.com/channels/Meetup-RSVP
 - Important:
 Replace AppKeyForMeetupRSVP with the Appkey for [Meetup-RSVP Channel]
 */
let appKey = "AppKeyForMeetupRSVP"
let url : String = "wss://open-data.api.satori.com"
let channelName = "Meetup-RSVP"
//: __MapAnnotation class for placing Annotations on the map__
class MapAnnotation: NSObject, MKAnnotation {
    var mapCoordinate: CLLocationCoordinate2D;
    
    init(mapCoordinate: CLLocationCoordinate2D) {
        self.mapCoordinate = mapCoordinate
    }
    
    var coordinate: CLLocationCoordinate2D {
        return mapCoordinate
    }
}
//: __Set the zoom level and size for map__
let delta = 1.0
let frame = CGRect( x:0, y:0, width:600, height:600 )
let mapView = MKMapView( frame: frame )
//: __View the map in the timeline__
PlaygroundPage.current.liveView = mapView
//: __Define the PduHandler. This will be called by Satori rtm when there is activity for the subscribe success/error response and subscription data responses.__
let handler : PduHandler = {(SatoriPdu) -> Void in
    let action : rtm_action_t = SatoriPdu.action;
    switch action {
    case RTM_ACTION_SUBSCRIPTION_DATA:
        let body : NSDictionary = SatoriPdu.body as! NSDictionary;
        let arr = body.object(forKey: "messages") as! NSArray;
        let msg : NSDictionary = arr.object(at: 0) as! NSDictionary;
        let city = (msg.object(forKey: "city") as! String);
        let country = (msg.object(forKey: "country") as! String);
        let lat : Double = msg.object(forKey: "latitude") as! Double;
        let long : Double = msg.object(forKey: "longitude") as! Double;
        DispatchQueue.main.async {
            let place = MapAnnotation(mapCoordinate: CLLocationCoordinate2D(latitude: lat, longitude: long));
            mapView.addAnnotation(place);
        }
    default:
        break
    }
}
//: __Connect to Satori using SatoriRtmConnection. And subscribe to Meetup-RSVP channel using a View(formerly Filter) to show locations in the US where meetups are happening in real time__
/*:
 - Note:
 It is recommended to connect to Satori on a background queue as network activity on the main thread is not performance efficient. You may also create your own operation queues and dispatch the connection logic to those queues.
 */
DispatchQueue.global(qos: .background).async {
    let conn : SatoriRtmConnection? = SatoriRtmConnection(url: url, andAppkey: appKey);
    conn?.connect(pduHandler: handler)
    var requestId:UInt32 = 123;
    let view = "select count(*) as '#of participants', group.group_city as city, group.group_country as country, group.group_lon as longitude, group.group_lat as latitude from `Meetup-RSVP` where country like \"us\" group by city";
    
    let body : NSDictionary = NSDictionary(objects: [view,channelName], forKeys: ["filter" as NSCopying,"subscription_id" as NSCopying]);
    
    do {
        let jsonData = try JSONSerialization.data(withJSONObject: body, options: .prettyPrinted)
        // here "jsonData" is the dictionary encoded in JSON data
        let str : String? = String(data: jsonData, encoding: .utf8);
        conn?.subscribe(withBody: str!, andRequestId: &requestId);
        while ((conn?.poll().rawValue)! >= 0) {
            sleep(1);
        }
    } catch {
        print(error.localizedDescription)
    }
}