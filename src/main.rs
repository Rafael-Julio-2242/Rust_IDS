use etherparse::err::ipv4;
use pcap::{Capture, Device};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use etherparse::PacketHeaders;


struct IntrusionDetection {
    port_scans: HashMap<String, Instant>,
}

impl IntrusionDetection {
    fn new() -> Self {
        Self {
            port_scans: HashMap::new(),
        }
    }

    fn detect_port_scan(&mut self, ip: String) {
        let now = Instant::now();
        let threshold = Duration::new(10, 0);

        self.port_scans
            .entry(ip.clone())
            .and_modify(|time| {
                if now.duration_since(*time) < threshold {
                    println!("Potencial scan de porta detectado pelo IP: {}", ip);
                }
                *time = now;
            })
            .or_insert(now);
    }
}

fn main() {
    
    let mut cap = Capture::from_device("wlp0s20f3").unwrap()
        .promisc(true)
        .open().unwrap();

    // let mut detector = IntrusionDetection::new();

    while let Ok(packet) = cap.next_packet(){

        let data = packet.data;

        match PacketHeaders::from_ethernet_slice(data) {
            Ok(headers ) => {

                if let Some(net_headers) = headers.net {

                    if let Some(ipv4_info) = net_headers.ipv4_ref() {
                        let source_ip = ipv4_info.0.source.iter().map(|x| format!("{}", x)).collect::<Vec<String>>().join(".");
                        let destination_ip = ipv4_info.0.destination.iter().map(|x| format!("{}", x)).collect::<Vec<String>>().join(".");

                        println!("SOURCE: {} | DESTINATION: {}", source_ip, destination_ip);
                        
                    }

                }

            },
            Err(e) => {
                println!("Erro ao analisar o pacote> {:#?}", e);
            }
        }

    }

}
