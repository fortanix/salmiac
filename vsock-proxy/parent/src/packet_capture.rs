use pcap::{
    Active,
    Capture,
};
use log::info;

pub fn open_packet_capture(device : pcap::Device, mtu : u32) -> Result<Capture<Active>, String> {
    let device_name = device.name.clone();
    let capture = Capture::from_device(device)
        .map_err(|err| format!("Cannot create capture {:?}", err))?;

    info!("Capturing with device: {}", device_name);

    capture.promisc(true)
        .immediate_mode(true)
        .snaplen(mtu as i32)
        .open()
        .map_err(|err| format!("Cannot open capture {:?}", err))
}

#[cfg(debug_assertions)]
pub fn open_packet_capture_with_port_filter(device : pcap::Device, port : u32, mtu : u32) -> Result<Capture<Active>, String> {
    fn add_port_filter(mut capture : Capture<Active>, port : u32) -> Capture<Active> {
        capture.filter(&*format!("port {}", port)).expect("Cannot set pcap port filter.");
        capture
    }

    open_packet_capture(device, mtu).map(|c| add_port_filter(c, port))
}
