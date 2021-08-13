pub mod socket;
pub mod netlink;
pub mod packet_capture;
pub mod device;

use pnet_datalink::MacAddr;

use std::net::{
    IpAddr,
    Ipv6Addr,
    Ipv4Addr
};

pub fn vec_to_ip(vec : &Vec<u8>) -> Result<IpAddr, String> {
    if vec.len() == 4 {
        Ok(IpAddr::V4(Ipv4Addr::new(
            vec[0],
            vec[1],
            vec[2],
            vec[3])))
    }
    else if vec.len() == 8 {
        Ok(IpAddr::V6(Ipv6Addr::new(
            vec[0] as u16,
            vec[1] as u16,
            vec[2] as u16,
            vec[3] as u16,
            vec[4] as u16,
            vec[5] as u16,
            vec[6] as u16,
            vec[7] as u16)))
    }
    else {
        Err("Vector must have 4 or 8 elements".to_string())
    }
}

pub fn vec_to_mac(vec : &Vec<u8>) -> Result<MacAddr, String> {
    if vec.len() == 6 {
        Ok(MacAddr(
            vec[0] as u8,
            vec[1] as u8,
            vec[2] as u8,
            vec[3] as u8,
            vec[4] as u8,
            vec[5] as u8
        ))
    }
    else {
        Err("Vector must have 6 elements".to_string())
    }
}