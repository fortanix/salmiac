/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use async_trait::async_trait;
use rtnetlink::packet::{RouteMessage, AF_INET, RTN_UNICAST};
use serde::{Deserialize, Serialize};

use crate::extract_enum_value;
use crate::netlink::next_in_stream;
use crate::netlink::Netlink;

use ipnetwork::{Ipv4Network, Ipv6Network};
use std::convert::TryFrom;
use std::net::IpAddr;

/// Netlink functions to manipulate routing table
#[async_trait]
pub trait NetlinkRoute {
    async fn add_route_for_device(&self, device_index: u32, route: &Route) -> Result<(), String>;

    async fn add_gateway(&self, gateway: &Gateway) -> Result<(), String>;

    async fn get_routes_for_device(&self, device_index: u32, version: rtnetlink::IpVersion) -> Result<GetRoutesResult, String>;
}

#[async_trait]
impl NetlinkRoute for Netlink {
    async fn add_route_for_device(&self, device_index: u32, route: &Route) -> Result<(), String> {
        let request = self
            .handle
            .route()
            .add()
            .output_interface(device_index)
            .scope(route.scope)
            .protocol(route.protocol)
            .table(route.table);

        match &route.address {
            RouteAddress::V4(route_address) => {
                let mut result = request.v4();

                if let Some(source) = route_address.source_l3_address {
                    result = result.source_prefix(source.network(), source.prefix());
                }

                if let Some(destination) = route_address.destination_l3_address {
                    result = result.destination_prefix(destination.network(), destination.prefix());
                }

                result.execute().await.map_err(|err| {
                    format!(
                        "Failed to add V4 route {:?} for device index {}. {:?}",
                        route, device_index, err
                    )
                })
            }
            RouteAddress::V6(route_address) => {
                let mut result = request.v6();

                if let Some(source) = route_address.source_l3_address {
                    result = result.source_prefix(source.network(), source.prefix());
                }

                if let Some(destination) = route_address.destination_l3_address {
                    result = result.destination_prefix(destination.network(), destination.prefix());
                }

                result.execute().await.map_err(|err| {
                    format!(
                        "Failed to add V6 route {:?} for device index {}. {:?}",
                        route, device_index, err
                    )
                })
            }
        }
    }

    async fn add_gateway(&self, gateway: &Gateway) -> Result<(), String> {
        let request = self
            .handle
            .route()
            .add()
            .scope(gateway.scope)
            .protocol(gateway.protocol)
            .table(gateway.table);

        match gateway.l3_address {
            IpAddr::V4(l3_address) => request
                .v4()
                .gateway(l3_address)
                .execute()
                .await
                .map_err(|err| format!("Failed to add V4 gateway {:?}. {:?}", gateway, err)),
            IpAddr::V6(l3_address) => request
                .v6()
                .gateway(l3_address)
                .execute()
                .await
                .map_err(|err| format!("Failed to add V6 gateway {:?}. {:?}", gateway, err)),
        }
    }

    async fn get_routes_for_device(&self, device_index: u32, version: rtnetlink::IpVersion) -> Result<GetRoutesResult, String> {
        let mut routes_stream = self.handle.route().get(version).execute();
        let mut routes: Vec<RouteMessage> = Vec::new();
        let mut gateway: Option<RouteMessage> = None;

        while let Some(route) = next_in_stream(&mut routes_stream).await? {
            if route.output_interface() == Some(device_index) && route.header.kind == RTN_UNICAST {
                // default route has no destination or /0 destination
                if route.destination_prefix().map_or(true, |(_, prefix)| prefix == 0) {
                    gateway = Some(route);
                } else {
                    routes.push(route);
                }
            }
        }

        Ok(GetRoutesResult { routes, gateway })
    }
}

pub struct GetRoutesResult {
    pub routes: Vec<RouteMessage>,

    pub gateway: Option<RouteMessage>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Route {
    pub protocol: u8,

    pub scope: u8,

    pub table: u8,

    pub address: RouteAddress,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum RouteAddress {
    V4(RouteAddressV4),
    V6(RouteAddressV6),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RouteAddressV4 {
    pub source_l3_address: Option<Ipv4Network>,

    pub destination_l3_address: Option<Ipv4Network>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RouteAddressV6 {
    pub source_l3_address: Option<Ipv6Network>,

    pub destination_l3_address: Option<Ipv6Network>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Gateway {
    pub protocol: u8,

    pub scope: u8,

    pub table: u8,

    pub l3_address: IpAddr,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum IpVersion {
    V4,
    V6,
}

impl TryFrom<&RouteMessage> for Route {
    type Error = String;

    fn try_from(route: &RouteMessage) -> Result<Self, Self::Error> {
        fn v4_network(address: Option<(IpAddr, u8)>) -> Result<Option<Ipv4Network>, String> {
            match address {
                Some((addr, prefix)) => {
                    let ipv4 = extract_enum_value!(addr, IpAddr::V4(e) => e)?;

                    let result =
                        Ipv4Network::new(ipv4, prefix).map_err(|err| format!("Failed creating IpNetwork. {:?}", err))?;

                    Ok(Some(result))
                }
                _ => Ok(None),
            }
        }

        fn v6_network(address: Option<(IpAddr, u8)>) -> Result<Option<Ipv6Network>, String> {
            match address {
                Some((addr, prefix)) => {
                    let ipv6 = extract_enum_value!(addr, IpAddr::V6(e) => e)?;

                    let result =
                        Ipv6Network::new(ipv6, prefix).map_err(|err| format!("Failed creating IpNetwork. {:?}", err))?;

                    Ok(Some(result))
                }
                _ => Ok(None),
            }
        }

        let address = if route.header.address_family == (AF_INET as u8) {
            RouteAddress::V4(RouteAddressV4 {
                source_l3_address: v4_network(route.source_prefix())?,
                destination_l3_address: v4_network(route.destination_prefix())?,
            })
        } else {
            RouteAddress::V6(RouteAddressV6 {
                source_l3_address: v6_network(route.source_prefix())?,
                destination_l3_address: v6_network(route.destination_prefix())?,
            })
        };

        Ok(Self {
            protocol: route.header.protocol,
            scope: route.header.scope,
            table: route.header.table,
            address,
        })
    }
}

impl TryFrom<&RouteMessage> for Gateway {
    type Error = String;

    fn try_from(route: &RouteMessage) -> Result<Self, Self::Error> {
        let l3_address = route.gateway().ok_or("Gateway route must have a gateway address.")?;

        Ok(Self {
            protocol: route.header.protocol,
            scope: route.header.scope,
            table: route.header.table,
            l3_address,
        })
    }
}
