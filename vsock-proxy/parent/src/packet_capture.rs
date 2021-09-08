use log::info;
use pcap::{Active, Capture};
use pcap_async::{Handle, Config};
use futures::stream::Fuse;
use futures::StreamExt;

pub fn open_packet_capture(device : pcap::Device) -> Result<Capture<Active>, String> {
    let device_name = device.name.clone();
    let capture = Capture::from_device(device)
        .map_err(|err| format!("Cannot create capture {:?}", err))?;

    info!("Capturing with device: {}", device_name);

    capture.open().map_err(|err| format!("Cannot open capture {:?}", err))
}

pub fn open_packet_capture_with_port_filter(device : pcap::Device, port : u32) -> Result<Capture<Active>, String> {
    fn add_port_filter(mut capture : Capture<Active>, port : u32) -> Capture<Active> {
        capture.filter(&*format!("port {}", port)).expect("Cannot set pcap port filter.");
        capture
    }

    open_packet_capture(device).map(|c| add_port_filter(c, port))
}

pub fn open_async_packet_capture_with_port_filter(device_name : &str, mtu : u32, port : u32) -> Result<Fuse<pcap_async::PacketStream>, String> {
    let mut config = async_packet_capture_config(mtu);
    config.with_bpf(format!("port {}", port));

    open_async_packet_capture0(device_name, config)
}

pub fn open_async_packet_capture(device_name : &str, mtu : u32) -> Result<Fuse<pcap_async::PacketStream>, String> {
    open_async_packet_capture0(device_name, async_packet_capture_config(mtu))
}

fn open_async_packet_capture0(device_name : &str, config : Config) -> Result<Fuse<pcap_async::PacketStream>, String> {
    let handle = Handle::live_capture(device_name)
        .map_err(|err| format!("Cannot create capture for device {}, error: {:?}", device_name, err))?;

    handle.set_immediate_mode().map_err(|err| format!("Failed to set pcap immediate mode {:?}", err))?;

    pcap_async::PacketStream::new(config, handle)
        .map(|e| e.fuse())
        .map_err(|err| format!("Cannot open async capture {:?}", err))
}

fn async_packet_capture_config(mtu : u32) -> Config {
    let mut config = Config::default();
    config.with_snaplen(mtu);
    config.with_blocking(false);

    config
}
