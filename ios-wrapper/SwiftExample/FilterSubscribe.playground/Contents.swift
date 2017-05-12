import MapKit
import PlaygroundSupport
import SatoriRtmSdkWrapper
//: ![Satori](SatoriLogo.jpg)
//: ## Using Filters with Open Data Channels

let url : String = "wss://open-data.api.satori.com"
let appKey = "AppKeyForMeetupRSVP"
let channelName = "Meetup-RSVP"

class MapAnnotation: NSObject, MKAnnotation {
    var mapCoordinate: CLLocationCoordinate2D;
    
    init(mapCoordinate: CLLocationCoordinate2D) {
        self.mapCoordinate = mapCoordinate
    }
    
    var coordinate: CLLocationCoordinate2D {
        return mapCoordinate
    }
}

// set the zoom
let delta = 1.0

// set the size of the map
let frame = CGRect( x:0, y:0, width:600, height:600 )
let mapView = MKMapView( frame: frame )
// view the map in the timeline!
PlaygroundPage.current.liveView = mapView

let handler : PduHandler = {(SatoriPdu) -> Void in
    let action : String = SatoriPdu.action;
    if action == "rtm/subscription/data" {
        if (SatoriPdu.body as? NSDictionary != nil) {
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
        }
    }
}

DispatchQueue.global(qos: .background).async {
    let conn : SatoriRtmConnection? = SatoriRtmConnection(url: url, andAppkey: appKey);
    conn?.connect(pduHandler: handler)
    var requestId:UInt32 = 123;
    let filter = "select count(*) as '#of participants', group.group_city as city, group.group_country as country, group.group_lon as longitude, group.group_lat as latitude from `Meetup-RSVP` where country like \"us\" group by city";
    
    let body : NSDictionary = NSDictionary(objects: [filter,channelName], forKeys: ["filter" as NSCopying,"subscription_id" as NSCopying]);
    
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


