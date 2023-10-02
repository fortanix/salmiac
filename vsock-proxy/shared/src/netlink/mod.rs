/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub mod arp;
pub mod route;

use async_trait::async_trait;
use futures::stream::TryStreamExt;
use futures::TryStream;
use rtnetlink::packet::LinkMessage;
use tokio::task::JoinHandle;

use crate::find_map;

use std::ops::Deref;

pub struct Netlink {
    handle: rtnetlink::Handle,

    _connection: JoinHandle<()>,
}

impl Netlink {
    pub fn new() -> Self {
        let (connection, handle, _) = rtnetlink::new_connection()
            .map_err(|err| format!("{:?}", err))
            .expect("Failed to connect to netlink");

        let _connection = tokio::spawn(connection);

        Netlink { handle, _connection }
    }
}

/// Netlink functions to manipulate information specific to network devices
#[async_trait]
pub trait NetlinkCommon {
    async fn get_link_for_device(&self, device_index: u32) -> Result<Option<LinkMessage>, String>;

    async fn set_link_for_device(&self, device_index: u32, mac_address: &[u8; 6]) -> Result<(), String>;
}

#[async_trait]
impl NetlinkCommon for Netlink {
    async fn get_link_for_device(&self, device_index: u32) -> Result<Option<LinkMessage>, String> {
        let mut links = self.handle.link().get().match_index(device_index).execute();

        let mut result: Option<LinkMessage> = None;
        while let Some(link) = next_in_stream(&mut links).await? {
            match result {
                None => result = Some(link),
                _ => {
                    return Err(format!(
                        "Device with index {} should have only one link. Found link: {:?}",
                        device_index, link
                    ))
                }
            }
        }

        Ok(result)
    }

    async fn set_link_for_device(&self, device_index: u32, mac_address: &[u8; 6]) -> Result<(), String> {
        self.handle
            .link()
            .set(device_index)
            .address(mac_address.to_vec())
            .execute()
            .await
            .map_err(|err| format!("Failed to set MAC address {:?}", err))
    }
}

pub trait LinkMessageExt {
    fn address(&self) -> Option<&[u8]>;

    fn mtu(&self) -> Option<u32>;
}

impl LinkMessageExt for LinkMessage {
    fn address(&self) -> Option<&[u8]> {
        use rtnetlink::packet::rtnl::link::nlas::Nla;

        find_map!(&self.nlas, Nla::Address(v) => v.deref())
    }

    fn mtu(&self) -> Option<u32> {
        use rtnetlink::packet::rtnl::link::nlas::Nla;

        find_map!(&self.nlas, Nla::Mtu(result) => *result)
    }
}

async fn next_in_stream<T, S>(stream: &mut S) -> Result<Option<T>, String>
where
    S: TryStream<Ok = T, Error = rtnetlink::Error> + Unpin,
{
    stream
        .try_next()
        .await
        .map_err(|err| format!("Failed to get next item {:?}", err))
}
