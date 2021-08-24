pub mod socket;
pub mod netlink;
pub mod packet_capture;
pub mod device;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::convert::TryFrom;

pub fn vec_to_ip4(vec : &[u8]) -> Result<Ipv4Addr, String> {
    let as_array = <[u8; 4]>::try_from(&vec[..])
        .map_err(|err| format!("Cannot convert vec to array {:?}", err))?;

    Ok(Ipv4Addr::from(as_array))
}

pub fn vec_to_ip6(vec : &[u16]) -> Result<Ipv6Addr, String> {
    let as_array = <[u16; 8]>::try_from(&vec[..])
        .map_err(|err| format!("Cannot convert vec to array {:?}", err))?;

    Ok(Ipv6Addr::from(as_array))
}