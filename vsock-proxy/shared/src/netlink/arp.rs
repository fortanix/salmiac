use rtnetlink::packet::NeighbourMessage;
use rtnetlink::IpVersion;
use serde::{Deserialize, Serialize};

use crate::find_map;
use crate::netlink::next_in_stream;
use crate::vec_to_ip4;

use std::convert::TryFrom;
use std::net::IpAddr;
use std::ops::Deref;

pub async fn add_neighbour(handle: &rtnetlink::Handle, device_index: u32, arp_entry: &ARPEntry) -> Result<(), String> {
    handle
        .neighbours()
        .add(device_index, arp_entry.l3_address)
        .link_local_address(&arp_entry.l2_address)
        .state(arp_entry.state)
        .flags(arp_entry.flags)
        .ntype(arp_entry.ntype)
        .execute()
        .await
        .map_err(|err| format!("Failed to create ARP entry {:?}", err))
}

pub async fn get_neighbours(handle: &rtnetlink::Handle) -> Result<Vec<NeighbourMessage>, String> {
    let mut neighbours = handle.neighbours().get().set_family(IpVersion::V4).execute();

    let mut result: Vec<NeighbourMessage> = Vec::new();
    while let Some(neighbour) = next_in_stream(&mut neighbours).await? {
        result.push(neighbour);
    }

    Ok(result)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ARPEntry {
    pub l2_address: [u8; 6],

    pub l3_address: IpAddr,

    pub state: u16,

    pub flags: u8,

    pub ntype: u8,
}

impl TryFrom<&NeighbourMessage> for ARPEntry {
    type Error = String;

    fn try_from(neighbour: &NeighbourMessage) -> Result<Self, Self::Error> {
        let l2_address = neighbour
            .l2_address()
            .map(|e| <[u8; 6]>::try_from(&e[..]))
            .expect("ARP entry should have a link local address!")
            .map_err(|err| format!("Cannot convert array slice {:?}", err))?;

        let destination = neighbour
            .destination()
            .map(|e| vec_to_ip4(e))
            .expect("ARP entry should have a destination!")
            .map_err(|err| format!("Cannot convert destination to IpAddr {:?}", err))?;

        Ok(Self {
            l2_address,
            l3_address: IpAddr::V4(destination),
            state: neighbour.header.state,
            flags: neighbour.header.flags,
            ntype: neighbour.header.ntype,
        })
    }
}

pub trait NeighbourMessageExt {
    fn l2_address(&self) -> Option<&[u8]>;

    fn destination(&self) -> Option<&[u8]>;
}

impl NeighbourMessageExt for NeighbourMessage {
    fn l2_address(&self) -> Option<&[u8]> {
        use rtnetlink::packet::neighbour::Nla;

        find_map!(&self.nlas, Nla::LinkLocalAddress(v) => v.deref())
    }

    fn destination(&self) -> Option<&[u8]> {
        use rtnetlink::packet::neighbour::Nla;

        find_map!(&self.nlas, Nla::Destination(v) => v.deref())
    }
}
