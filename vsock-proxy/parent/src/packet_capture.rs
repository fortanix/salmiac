/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::collections::HashSet;

use futures::{SinkExt, StreamExt};
use log::{info, warn};
use pcap::{Active, Capture, Device, Direction, Packet, PacketCodec};
use shared::socket::{AsyncReadLvStream, AsyncWriteLvStream};
use tokio::io;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::task::JoinHandle;
use tokio_vsock::VsockStream as AsyncVsockStream;

use crate::network::{recompute_packet_checksum, ChecksumComputationError};

pub(crate) struct PcapLoopsResult {
    pub(crate) pcap_to_vsock: JoinHandle<Result<(), String>>,

    pub(crate) vsock_to_pcap: JoinHandle<Result<(), String>>,
}

/// Starts two network forwarding tasks which allow networking to function inside a parent.
/// One task forwards packets from pcap device and into the vsock and other does the same in the opposite direction.
/// Network forwarding tasks never exit during normal parent execution and it is considered an error if they do.
/// # Returns
/// Handles to two network forwarding tasks
pub(crate) fn start_pcap_loops(network_device: Device, vsock: AsyncVsockStream) -> Result<PcapLoopsResult, String> {
    let read_capture = open_packet_capture(network_device.clone(), Mode::Read)?;
    let write_capture = open_packet_capture(network_device, Mode::Write)?;

    let (vsock_read, vsock_write) = io::split(vsock);

    let pcap_to_vsock = tokio::spawn(read_from_device_async(read_capture, vsock_write));

    let vsock_to_pcap = tokio::spawn(write_to_device_async(write_capture, vsock_read));

    Ok(PcapLoopsResult {
        pcap_to_vsock,
        vsock_to_pcap,
    })
}

async fn read_from_device_async(
    capture: Capture<Active>,
    mut enclave_stream: WriteHalf<AsyncVsockStream>,
) -> Result<(), String> {
    struct Raw;

    impl PacketCodec for Raw {
        type Item = Result<Vec<u8>, String>;

        fn decode(&mut self, packet: Packet) -> Self::Item {
            if packet.header.caplen == packet.header.len {
                Ok(packet.data.to_owned())
            } else {
                Err(format!(
                    "Dropped PCAP captured packet! \
                        Reason: captured packet length ({} bytes) \
                        is different than the inbound packet length ({} bytes).",
                    packet.header.caplen,
                    packet.header.len
                ))
            }
        }
    }

    let mut unsupported_protocols = HashSet::<u8>::new();

    let mut capture = capture.stream(Raw)
        .map_err(|err| format!("Failed to convert capture to stream: {:?}", err))?;

    while let Some(pkt) = capture.next().await {
        if let Err(err) = async {
            let mut data = pkt.map_err(|err| format!("error reading from pcap device: {:?}", err))??;
            match recompute_packet_checksum(&mut data) {
                Err(ChecksumComputationError::UnsupportedProtocol(protocol)) => {
                    if unsupported_protocols.insert(protocol) {
                        warn!(
                            "Unsupported protocol {} encountered when recomputing checksum for a packet.",
                            protocol
                        );
                    }
                }
                Err(ChecksumComputationError::Err(err)) => {
                    return Err(format!("error recomputing packet checksum: {:?}", err));
                }
                Ok(_) => {}
            }

            enclave_stream.write_lv_bytes(&data).await
                .map_err(|err| format!("error writing to vsock {:?}", err))
        }.await {
            warn!("Failed to process packet towards enclave: {}", err);
        }
    };

    Ok(())
}

async fn write_to_device_async(
    capture: Capture<Active>,
    mut from_enclave: ReadHalf<AsyncVsockStream>,
) -> Result<(), String> {
    let mut capture = capture.sink()
        .map_err(|err| format!("Failed to convert capture to sink: {:?}", err))?;
    loop {
        if let Err(err) = async {
            let packet = from_enclave
                .read_lv_bytes()
                .await
                .map_err(|err| format!("error reading from vsock: {:?}", err))?;

            capture.send(packet).await
                .map_err(|err| format!("error writing to pcap device: {:?}", err))
        }.await {
            warn!("Failed to process packet from enclave: {}", err);
        }
    }
}

enum Mode {
    Read,
    Write,
}

fn open_packet_capture(device: pcap::Device, mode: Mode) -> Result<Capture<Active>, String> {
    let device_name = device.name.clone();
    let capture = Capture::from_device(device).map_err(|err| format!("Cannot create capture {:?}", err))?
        .immediate_mode(true);

    if let Mode::Read = mode {
        info!("Capturing with device: {}", device_name);
    }

    let mut capture = capture.open().map_err(|err| format!("Cannot open capture {:?}", err))?;
    capture = capture.setnonblock().map_err(|err| format!("Failed to configure pcap non-blocking mode {:?}", err))?;

    if let Mode::Read = mode {
        // We capture only incoming packets inside the parent, however by default pcap
        // captures all the packets that come through the network device (like
        // tcpdump). Without this filter what would happen is that pcap will capture
        // packets forwarded from enclave's TAP device, which in turn
        // will get forwarded back into the enclave by the parent.
        // This doesn't break the networking as incorrect packets will get dropped by
        // the enclave, but that way it generates unnecessary traffic that we don't
        // need.
        capture.direction(Direction::In).map_err(|err| format!("Failed to set pcap capture directoin {:?}", err))?;
    }

    Ok(capture)
}
