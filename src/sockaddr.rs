#![allow(non_upper_case_globals)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use nom::le_u16;

/// For convenience, the values of these constants match the values of AF_INET and AF_INET6 on Linux.
const kIPv4: u16 = 2;
const kIPv6: u16 = 10;

const kIPv4AddressSize: usize = 4;
const kIPv6AddressSize: usize = 16;

named!(pub socket_address<Option<SocketAddr>>, do_parse!(
    address_family: le_u16 >>
    ip: switch!(value!(address_family),
        kIPv4 => take!(kIPv4AddressSize) |
        kIPv6 => take!(kIPv6AddressSize)
    ) >>
    port: le_u16 >>
    (
        match address_family {
            kIPv4 => {
                Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*array_ref!(ip, 0, kIPv4AddressSize))), port))
            },
            kIPv6 => {
                Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*array_ref!(ip, 0, kIPv6AddressSize))), port))
            },
            _ => {
                None
            }
        }
    )
));
