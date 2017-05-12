import UIKit
import PlaygroundSupport
import SatoriRtmSdkWrapper
//: ![Satori](SatoriLogo.jpg)
//: ## Subscribing to an Open Data Channel
/*:
 [big-rss Channel]: https://www.satori.com/channels/big-rss
 - Important:
 Replace AppKeyForBigRss with the Appkey for [big-rss Channel]
 */
let appKey = "AppKeyForBigRss"
let url : String = "wss://open-data.api.satori.com"
let channelName = "big-rss"
//: __Container view to host the textView__
let hostView = UIView(frame: CGRect(x: 0, y: 0, width: 500, height: 800))
hostView.backgroundColor = .lightGray
PlaygroundPage.current.liveView = hostView
//: __TextView that shows RSS Title and Published On information__
let rssTextView = UITextView(frame: .zero)
rssTextView.translatesAutoresizingMaskIntoConstraints = false
rssTextView.text = ""
rssTextView.isEditable = false;
rssTextView.isScrollEnabled = true;
rssTextView.font = UIFont(name: "Menlo-Regular", size: 13)
rssTextView.textColor = .white
rssTextView.backgroundColor = .black
//: __Create a StackView to contain the rssTextView and add it to hostView__
let hostStackView = UIStackView(arrangedSubviews: [rssTextView])
hostStackView.frame = hostView.bounds
hostStackView.axis = .vertical
hostStackView.spacing = 1
rssTextView.heightAnchor.constraint(equalToConstant: 200).isActive = true
hostView.addSubview(hostStackView)
hostView
//: __Define the PduHandler. This will be called by Satori rtm when there is activity for the subscribe success/error response and subscription data responses.__
let handler : PduHandler = {(SatoriPdu) -> Void in
    let action : String = SatoriPdu.action;
    if action == "rtm/subscription/data" {
        if (SatoriPdu.body as? NSDictionary != nil) {
            let body : NSDictionary = SatoriPdu.body as! NSDictionary;
            let arr = body.object(forKey: "messages") as! NSArray;
            let msg : NSDictionary = arr.object(at: 0) as! NSDictionary;
            let title = (msg.object(forKey: "title") as! String);
            let publishedTs = (msg.object(forKey: "publishedTimestamp") as! String);
            DispatchQueue.main.async {
                rssTextView.text = rssTextView.text + "\n -------------------------------------------------------";
                rssTextView.text = rssTextView.text + "\n Title:" + title + "\n Published On:" + publishedTs + "\n";
                let range = NSMakeRange(rssTextView.text.characters.count - 1, 1);
                rssTextView.scrollRangeToVisible(range);
            }
        }
    }
}
//: __Connect to Satori using SatoriRtmConnection. And subscribe to big-rss channel to show title and published on date in real time__
/*:
 - Note:
 It is recommended to connect to Satori on a background queue as network activity on the main thread is not performance efficient. You may also create your own operation queues and dispatch the connection logic to those queues.
 */
DispatchQueue.global(qos: .background).async {
    let conn : SatoriRtmConnection? = SatoriRtmConnection(url: url, andAppkey: appKey);
    conn?.connect(pduHandler: handler)
    var requestId:UInt32 = 123;
    conn?.subscribe(channelName, andRequestId: &requestId);
    while ((conn?.poll().rawValue)! >= 0) {
        sleep(1);
    }
}
