import UIKit
import PlaygroundSupport
import SatoriRtmSdkWrapper

//: ## Subscribing to an Open Data Channel

let url : String = "wss://open-data.api.satori.com"
let appKey = "AppKeyForBigRss"
let channelName = "big-rss"

let hostView = UIView(frame: CGRect(x: 0, y: 0, width: 500, height: 800))
hostView.backgroundColor = .lightGray
PlaygroundPage.current.liveView = hostView

let titleTextView = UITextView(frame: .zero)
titleTextView.translatesAutoresizingMaskIntoConstraints = false
titleTextView.text = ""
titleTextView.isEditable = false;
titleTextView.isScrollEnabled = true;
titleTextView.font = UIFont(name: "Menlo-Regular", size: 13)
titleTextView.textColor = .white
titleTextView.backgroundColor = .black

let hostStackView = UIStackView(arrangedSubviews: [titleTextView])
hostStackView.frame = hostView.bounds
hostStackView.axis = .vertical
hostStackView.spacing = 1
titleTextView.heightAnchor.constraint(equalToConstant: 200).isActive = true
hostView.addSubview(hostStackView)
hostView

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
                titleTextView.text = titleTextView.text + "\n -------------------------------------------------------";
                titleTextView.text = titleTextView.text + "\n Title:" + title + "\n Published On:" + publishedTs + "\n";
                let range = NSMakeRange(titleTextView.text.characters.count - 1, 1);
                titleTextView.scrollRangeToVisible(range);
            }
        }
    }
}

DispatchQueue.global(qos: .background).async {
    let conn : SatoriRtmConnection? = SatoriRtmConnection(url: url, andAppkey: appKey);
    conn?.connect(pduHandler: handler)
    var requestId:UInt32 = 123;
    conn?.subscribe(channelName, andRequestId: &requestId);
    while ((conn?.poll().rawValue)! >= 0) {
        sleep(1);
    }
}
