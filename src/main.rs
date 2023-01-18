use pcap;
use packet;
use packet::Packet;
use chrono;
use chrono::TimeZone;
use std::sync::{Arc, Barrier, RwLock};
use std::thread;
use std::process;
use syslog;
use std::path::Path;
use twilio::{OutboundMessage, TwilioError};
use tokio::runtime::Runtime;

mod config;

fn describe_maybe_ipv4<B: AsRef<[u8]>>(
                        dev: &str,
                        e_pack: &packet::ether::Packet<B>,
                        pcap_time: &chrono::DateTime<chrono::Local>) -> String
{

    let e_src = e_pack.source().to_string();
    let e_dst = e_pack.destination().to_string();
    let e_proto: u16 = e_pack.protocol().into();
   
    return match packet::ip::v4::Packet::new(e_pack.payload()) {
        Ok(_ipv4) => format!("{} {} [ipv4] ether-src:{} ether-dst:{} ip-src:{} ip-dst:{}\n",
            dev,
            pcap_time.to_string(),
            e_src, e_dst, 
            _ipv4.source().to_string(),
            _ipv4.destination().to_string()),
        Err(_) => format!("{} {} [non-ipv4] ether-src:{} ether-dst:{} proto:{}\n",
            dev,
            pcap_time.to_string(), 
            e_src, e_dst, e_proto)
    };
}

fn describe_ether<B: AsRef<[u8]>>(
                  dev: &str,
                  e_pack: &packet::ether::Packet<B>,
                  pcap_time: &chrono::DateTime<chrono::Local>) -> String
{
    let e_src = e_pack.source().to_string();
    let e_dst = e_pack.destination().to_string();
    let e_proto:u16 = e_pack.protocol().into();
   
    return match e_pack.protocol() {
        packet::ether::Protocol::Ipv4 => describe_maybe_ipv4(
                dev,
                &e_pack,
                &pcap_time),
        _ => format!("{} {} [non-ipv4] ether-src:{} ether-dst:{} proto:{}\n",
                dev,
                pcap_time.to_string(), 
                e_src, e_dst, e_proto)
    };
}

fn describe_raw(dev: &str, 
                pcap_time: &chrono::DateTime<chrono::Local>) -> String 
{
    return format!("{} {} [non-ether]\n", 
            dev, pcap_time.to_string());
}

fn describe_capture(dev: &str) -> String
{
    return format!("starting packet capture on {}\n", dev);
}

fn do_syslog(logmsg: &str) {
    let fmter = syslog::Formatter3164 { 
            facility: syslog::Facility::LOG_LOCAL7,
            hostname: None, // syslog fills this in automatically
            process: "letmeknow".into(),
            pid: process::id() as i32};

    let mut logger = syslog::unix(fmter).unwrap();
    logger.notice(logmsg).unwrap();
}

async fn do_sms(_logmsg: &str, c: &config::TwilioConfig) 
    -> Result<(), TwilioError> 
{
    let client = twilio::Client::new(c.account_id.as_str(), c.auth_token.as_str());
    for recv in &c.sms_receivers {
        client.send_message(OutboundMessage::new(c.sms_sender.as_str(), recv,
                                _logmsg)).await?;
    }
    Ok(())
}

fn thread_routine(last_log: Arc<RwLock<chrono::DateTime<chrono::Local>>>, 
                  last_alert: Arc<RwLock<chrono::DateTime<chrono::Local>>>, 
                  iface: pcap::Device, 
                  tz: &chrono::Local,
                  c: config::LMKConfig)
{
    let dev_str = iface.name.clone();
    let mut cap = iface.open().unwrap();
    cap.set_datalink(pcap::Linktype(1)).unwrap(); // capture Ethernet link-type
    // leave ARP and excluded traffic out (see "exclude" option in config)
    let bpf_expr = format!("inbound and not ether multicast and not ether broadcast and not ether proto \\arp and not ip multicast and not ip broadcast and not ip6 multicast{}", c.traffic.exclude_bpf);

    cap.filter(bpf_expr.as_str(), false).unwrap();

    let will_store_pcaps : bool = match c.pcap_dumps {
            Some(_) => true,
            None => false
    };

    let mut pcapfile = match will_store_pcaps {
        true => cap.savefile(Path::new(format!("{}/{}.pcap", c.pcap_dumps.unwrap().path, &dev_str).as_str())).unwrap(),
        false => // can't believe I need to do this to keep this initialized!
            cap.savefile(Path::new("/dev/null")).unwrap()
    };

    let will_syslog = c.local_syslog;

    if will_syslog {
        do_syslog(describe_capture(&dev_str).as_str());
        do_syslog(format!("{}.bpf '{}'", &dev_str, &bpf_expr).as_str());
    }

    let will_use_twilio : bool = match c.twilio {
        Some(_) => true,
        None => false
    };

    while let Ok(pack) = cap.next() {
        let packet_time = tz.timestamp(pack.header.ts.tv_sec, 0);
        let should_syslog : bool;
        let should_alert : bool;

        if will_store_pcaps {
            pcapfile.write(&pack);
        }

        { 
            should_syslog = will_syslog && ((packet_time - *(last_log.read().unwrap())) >= 
                chrono::Duration::minutes(10));
        }

        {
            should_alert = will_use_twilio && ((packet_time - *(last_alert.read().unwrap())) >= 
                chrono::Duration::hours(6));
        }
        
        if !should_syslog && !should_alert {
            continue;
        }

        let packet_msg = match packet::ether::Packet::new(pack.data) {
            Ok(e) => describe_ether(&dev_str, &e, &packet_time),
            Err(_) => describe_raw(&dev_str, &packet_time)
        };

        if should_syslog {
            let mut latest_log_tstamp = last_log.write().unwrap();
            *latest_log_tstamp = packet_time.clone();
            do_syslog(packet_msg.as_str());
        }

        if should_alert {
            let mut latest_alert_tstamp = last_alert.write().unwrap();
            *latest_alert_tstamp = packet_time.clone();
            if let Err(e) = Runtime::new().expect("Failed to create Tokio runtime").block_on(do_sms(packet_msg.as_str(), &c.twilio.as_ref().unwrap())) {
               eprintln!("Error sending SMS: {:?}", e);
            }
        }

        if will_store_pcaps {
            pcapfile.flush().unwrap();
        }
    }
}

fn main() {
    let tz = chrono::Local::now().timezone();
    let config = config::LMKConfig::from_file();

    let mut devices = pcap::Device::list().unwrap(); // start with full set

    // filter pcap identified devices to retain only selected ones
    devices.retain(|d| config.traffic.ifaces.contains(&d.name));

    if devices.len() == 0 {
        panic!("No devices selected, exiting!");
    }

    // threading handles and barrier for synced termination
    let mut handles = Vec::with_capacity(devices.len());
    let barrier = Arc::new(Barrier::new(devices.len()));

    // Initialize both "last log" and "last alert" timestaps with EPOCH

    let last_log = Arc::new(RwLock::new(chrono::Local.timestamp(0,0)));
    let last_alert = Arc::new(RwLock::new(chrono::Local.timestamp(0,0)));

    for iface in devices {
        let b = Arc::clone(&barrier);
        let last_log = Arc::clone(&last_log);
        let last_alert = Arc::clone(&last_alert);
        let thread_local_config = config.clone();

        handles.push(
            thread::spawn(move || 
            { 
                thread_routine(last_log, last_alert, iface, &tz, thread_local_config); 
                b.wait(); 
            })
        );
    }

    barrier.wait();

    for handle in handles {
        handle.join().unwrap();
    }
}
