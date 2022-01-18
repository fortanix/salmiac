use log::info;
use pcap::{Active, Capture};
use pcap_async::{Handle, Config};
use futures::stream::Fuse;
use futures::StreamExt;

use shared::ETHERNET_HEADER_SIZE;

pub fn open_packet_capture(device : pcap::Device) -> Result<Capture<Active>, String> {
    let device_name = device.name.clone();
    let capture = Capture::from_device(device)
        .map_err(|err| format!("Cannot create capture {:?}", err))?;

    info!("Capturing with device: {}", device_name);

    capture.open().map_err(|err| format!("Cannot open capture {:?}", err))
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
    config.with_snaplen(ETHERNET_HEADER_SIZE + mtu);
    config.with_blocking(false);

    // We capture only incoming packets inside the parent, however by default pcap captures
    // all the packets that come through the network device (like tcpdump).
    // Without this filter what would happen is that pcap will capture packets forwarded from enclave's TAP device, which in turn
    // will get forwarded back into the enclave by the parent.
    // This doesn't break the networking as incorrect packets will get dropped by the enclave,
    // but that way it generates unnecessary traffic that we don't need.
    config.with_bpf("inbound".to_string());

    config
}
