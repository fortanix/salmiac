pub mod socket;
pub mod netlink;
pub mod packet_capture;
pub mod device;

use std::net::{
    IpAddr,
};
use std::convert::TryFrom;

pub fn vec_to_ip4(vec : &[u8]) -> Result<IpAddr, String> {
    let as_array = <[u8; 4]>::try_from(&vec[..])
        .map_err(|err| format!("Cannot convert vec to array {:?}", err))?;

    Ok(IpAddr::from(as_array))
}

pub fn vec_to_ip6(vec : &[u16]) -> Result<IpAddr, String> {
    let as_array = <[u16; 8]>::try_from(&vec[..])
        .map_err(|err| format!("Cannot convert vec to array {:?}", err))?;

    Ok(IpAddr::from(as_array))
}