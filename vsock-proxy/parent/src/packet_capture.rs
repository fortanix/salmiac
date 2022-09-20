use futures::stream::Fuse;
use futures::StreamExt;
use log::{info, warn};
use pcap::{Active, Capture, Device};
use pcap_async::{Config, Handle};
use tokio::io;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use tokio_vsock::VsockStream as AsyncVsockStream;

use crate::network::{recompute_packet_checksum, ChecksumComputationError};
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream};
use shared::{log_packet_processing, PACKET_LOG_STEP};

use std::collections::HashSet;
use std::sync::mpsc;
use std::sync::mpsc::TryRecvError;
use std::thread;

pub(crate) struct PcapLoopsResult {
    pub read_handle: JoinHandle<Result<(), String>>,

    pub write_handle: JoinHandle<Result<(), String>>,
}

pub(crate) fn start_pcap_loops(network_device: Device, vsock: AsyncVsockStream) -> Result<PcapLoopsResult, String> {
    let read_capture = open_async_packet_capture(&network_device.name)?;
    let write_capture = open_packet_capture(network_device)?;

    let (vsock_read, vsock_write) = io::split(vsock);

    let read_handle = tokio::spawn(read_from_device_async(read_capture, vsock_write));

    let write_handle = tokio::spawn(write_to_device_async(write_capture, vsock_read));

    Ok(PcapLoopsResult {
        read_handle,
        write_handle,
    })
}

async fn read_from_device_async(
    mut capture: Fuse<pcap_async::PacketStream>,
    mut enclave_stream: WriteHalf<AsyncVsockStream>,
) -> Result<(), String> {
    let mut count = 0 as u32;
    let mut unsupported_protocols = HashSet::<u8>::new();

    loop {
        let packets = match capture.next().await {
            Some(Ok(packets)) => packets,
            Some(Err(e)) => return Err(format!("Failed to read packet from pcap {:?}", e)),
            None => return Ok(()),
        };

        for packet in packets {
            if packet.actual_length() == packet.original_length() {
                let mut data = packet.into_data();

                match recompute_packet_checksum(&mut data) {
                    Err(ChecksumComputationError::Err(err)) => {
                        warn!("Failed recomputing checksum for a packet. {:?}", err);
                    }
                    Err(ChecksumComputationError::UnsupportedProtocol(protocol)) => {
                        if unsupported_protocols.insert(protocol) {
                            warn!(
                                "Unsupported protocol {} encountered when recomputing checksum for a packet.",
                                protocol
                            );
                        }
                    }
                    _ => {}
                }

                enclave_stream.write_lv_bytes(&data).await?;

                count = log_packet_processing(count, PACKET_LOG_STEP, "parent pcap");
            } else {
                warn!(
                    "Dropped PCAP captured packet! \
                        Reason: captured packet length ({} bytes) \
                        is different than the inbound packet length ({} bytes).",
                    packet.actual_length(),
                    packet.original_length()
                );
            }
        }
    }
}

async fn write_to_device_async(
    mut capture: Capture<Active>,
    mut from_enclave: ReadHalf<AsyncVsockStream>,
) -> Result<(), String> {
    let mut count = 0 as u32;
    let (packet_tx, packet_rx) = mpsc::channel();
    let (error_tx, error_rx) = mpsc::sync_channel(1);

    thread::spawn(move || {
        while let Ok(packet) = packet_rx.recv() {
            if let Err(e) = capture.sendpacket(packet) {
                let err = format!("Failed to write to pcap {:?}", e);

                error_tx.send(err).expect("Failed sending error");

                break;
            }
        }
    });

    loop {
        let packet = from_enclave
            .read_lv_bytes()
            .await
            .map_err(|err| format!("Failed to read packet from enclave {:?}", err))?;

        match error_rx.try_recv() {
            Err(TryRecvError::Disconnected) => {
                return Err(format!("pcap writer thread died prematurely"));
            }
            Ok(e) => return Err(e),
            _ => {}
        }

        packet_tx
            .send(packet)
            .map_err(|err| format!("Failed to send packet to pcap writer thread {:?}", err))?;

        count = log_packet_processing(count, PACKET_LOG_STEP, "parent vsock");
    }
}

fn open_packet_capture(device: pcap::Device) -> Result<Capture<Active>, String> {
    let device_name = device.name.clone();
    let capture = Capture::from_device(device).map_err(|err| format!("Cannot create capture {:?}", err))?;

    info!("Capturing with device: {}", device_name);

    capture.open().map_err(|err| format!("Cannot open capture {:?}", err))
}

fn open_async_packet_capture(device_name: &str) -> Result<Fuse<pcap_async::PacketStream>, String> {
    let config = async_packet_capture_config();

    let handle = Handle::live_capture(device_name)
        .map_err(|err| format!("Cannot create capture for device {}, error: {:?}", device_name, err))?;

    handle
        .set_immediate_mode()
        .map_err(|err| format!("Failed to set pcap immediate mode {:?}", err))?;

    pcap_async::PacketStream::new(config, handle)
        .map(|e| e.fuse())
        .map_err(|err| format!("Cannot open async capture {:?}", err))
}

fn async_packet_capture_config() -> Config {
    let mut config = Config::default();

    config.with_blocking(false);

    // We capture only incoming packets inside the parent, however by default pcap
    // captures all the packets that come through the network device (like
    // tcpdump). Without this filter what would happen is that pcap will capture
    // packets forwarded from enclave's TAP device, which in turn
    // will get forwarded back into the enclave by the parent.
    // This doesn't break the networking as incorrect packets will get dropped by
    // the enclave, but that way it generates unnecessary traffic that we don't
    // need.
    config.with_bpf("inbound".to_string());

    config
}
