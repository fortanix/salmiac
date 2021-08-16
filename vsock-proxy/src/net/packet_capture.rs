use pcap::{
    Active,
    Capture,
    Device
};
use log::info;
use crate::net::device::RichNetworkInterface;

pub fn open_packet_capture(interface : &RichNetworkInterface) -> Result<Capture<Active>, String> {
    let pcap_device = Device {
        name: interface.0.name.clone(),
        desc: None
    };

    let capture = Capture::from_device(pcap_device)
        .map_err(|err| format!("Cannot create capture {:?}", err))?;

    info!("Capturing with device: {}", &interface.0.name);

    let mtu = interface.get_mtu()?;

    capture.promisc(true)
        .immediate_mode(true)
        .snaplen(mtu)
        .open()
        .map_err(|err| format!("Cannot open capture {:?}", err))
}

#[cfg(debug_assertions)]
pub fn open_packet_capture_with_port_filter(interface : &RichNetworkInterface, port : u32) -> Result<Capture<Active>, String> {
    fn add_port_filter(mut capture : Capture<Active>, port : u32) -> Capture<Active> {
        capture.filter(&*format!("port {}", port)).expect("Cannot set pcap port filter.");
        capture
    }

    open_packet_capture(interface).map(|c| add_port_filter(c, port))
}
