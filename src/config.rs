use configparser::ini::Ini;

#[derive(Clone)]
pub struct TrafficConfig {
    pub ifaces : Vec<String>,
    pub exclude_bpf : String
}

#[derive(Clone)]
pub struct PCAPConfig {
    pub path: String
}

#[derive(Clone)]
pub struct TwilioConfig {
    pub account_id : String,
    pub auth_token : String,
    pub sms_sender : String,
    pub sms_receivers : Vec<String>
}

#[derive(Clone)]
pub struct LMKConfig {
    pub traffic : TrafficConfig,
    pub pcap_dumps : Option<PCAPConfig>,
    pub local_syslog : bool,
    pub twilio : Option<TwilioConfig>
}

impl LMKConfig {
    pub fn from_file() -> Self {
        let mut config = Ini::new();
        config.load("/etc/letmeknow/config.ini").unwrap_or_else(|error| {
                panic!("Problem opening / parsing config file: {:?}", error);
            });

        let ifaces = config.get("traffic", "capture_interfaces").unwrap_or(
            "".to_string());
        let ifaces_splitter = ifaces.split(",");
        let mut ifaces_vec = Vec::<String>::new();
        for iface in ifaces_splitter.into_iter() {
            ifaces_vec.push(iface.to_string());
        }

        let exclude = config.get("traffic", "exclude").unwrap_or(
            "".to_string());
        let exclude_splitter = exclude.split(",");
        let exclude_vec = exclude_splitter.collect::<Vec<&str>>();
        let mut bpf_expr = String::new();
        for val in exclude_vec.iter() {
            if *val != "" {
                bpf_expr.push_str(format!(" and not ip src {}", *val).as_str());
            }
        }

        let _traffic = TrafficConfig { ifaces: ifaces_vec, 
                                      exclude_bpf: bpf_expr };

        let use_pcaps : bool = match config.getbool("pcap_dumps", "use_pcap_dumps").unwrap_or(Some(true)) {
            Some(e) => e,
            None => true
        };

        let _pcap_dumps : Option<PCAPConfig>;
        if !use_pcaps {
            _pcap_dumps = None;
        } else {
            let pcap_path = config.get("pcap_dumps", "dump_dir").unwrap_or("/var/log/letmeknow/".to_string());

            _pcap_dumps = Some(PCAPConfig {path: pcap_path});
        }
       
        let _local_syslog = match config.getbool("syslog", "use_local_syslog").unwrap_or(Some(true)) {
            Some(e) => e,
            None => true
        };

        let _twilio : Option<TwilioConfig>;
        let use_twilio : bool = match config.getbool("twilio", "use_twilio").unwrap_or(Some(false)) {
            Some(e) => e,
            None => false
        };

        if !use_twilio {
            _twilio = None;
        } else {
            let twilio_account_id = config.get("twilio", 
                "twilio_account_id").unwrap_or("".to_string());
            let twilio_auth_token = config.get("twilio",
                "twilio_auth_token").unwrap_or("".to_string());
            let twilio_sms_sender = config.get("twilio",
                "twilio_sms_sender").unwrap_or("".to_string());
            let twilio_sms_receivers = config.get("twilio",
                "twilio_sms_receivers").unwrap_or("".to_string());
            let receivers_splitter = twilio_sms_receivers.split(",");
            let mut receivers_vec = Vec::<String>::new();
            for recv in receivers_splitter.into_iter() {
                receivers_vec.push(recv.to_string());
            }
            
            _twilio = Some( TwilioConfig { 
                account_id : twilio_account_id,
                auth_token : twilio_auth_token,
                sms_sender : twilio_sms_sender,
                sms_receivers : receivers_vec} );
        }

        return LMKConfig { 
            traffic: _traffic,
            pcap_dumps: _pcap_dumps,
            local_syslog: _local_syslog,
            twilio: _twilio
        }
    }
}
