// Dynamic Host Configuration Protocol

use std::{error::Error, net::UdpSocket};

use byteorder::{ByteOrder, NetworkEndian};
use simple_endian::BigEndian;

/// Size of IPv4 adderess in octets.
///
/// [RFC 8200 § 2]: https://www.rfc-editor.org/rfc/rfc791#section-3.2
pub const ADDR_SIZE: usize = 4;

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Ipv4Addr(pub [u8; ADDR_SIZE]);

impl Ipv4Addr {
    const EMPTY: Self = Self([0; ADDR_SIZE]);
}

// FIXME: The MAC address is usually obtained by using getifaddrs() which currently
//        is unimplemented in mlibc.
const MAC_ADDRESS: &[u8] = &[52, 54, 0, 12, 34, 56];
const DHCP_XID: u32 = 0x43424140;

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
enum DhcpType {
    BootRequest = 1u8.swap_bytes(),
    // BootReply = 2u8.swap_bytes(),
}

#[derive(Debug, Copy, Clone)]
#[repr(u8)]
enum HType {
    Ethernet = 1u8.swap_bytes(),
}

#[derive(Debug, Clone)]
#[repr(C, packed)]
struct Header {
    op: DhcpType,
    htype: HType,
    hlen: BigEndian<u8>,
    hops: BigEndian<u8>,
    xid: BigEndian<u32>,
    seconds: BigEndian<u16>,
    flags: BigEndian<u16>,
    client_ip: Ipv4Addr,
    your_ip: Ipv4Addr,
    server_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
    client_hw_addr: [u8; 16],
    server_name: [u8; 64],
    file: [u8; 128],
    options: [u8; 64],
}

impl Header {
    fn new(htype: HType) -> Self {
        let mut client_hw_addr = [0; 16];
        client_hw_addr[0..6].copy_from_slice(MAC_ADDRESS);

        Self {
            htype,
            hlen: BigEndian::<u8>::from(6),
            hops: BigEndian::<u8>::from(0),
            xid: BigEndian::<u32>::from(DHCP_XID),
            seconds: BigEndian::<u16>::from(0),
            client_hw_addr,
            server_name: [0; 64],
            file: [0; 128],
            options: [0; 64],

            // request info:
            op: DhcpType::BootRequest,
            flags: BigEndian::from(0x8000), // broadcast
            client_ip: Ipv4Addr::EMPTY,
            your_ip: Ipv4Addr::EMPTY,
            server_ip: Ipv4Addr::EMPTY,
            gateway_ip: Ipv4Addr::EMPTY,
        }
    }

    fn options_mut(&mut self) -> OptionsWriter<'_> {
        OptionsWriter::new(&mut self.options)
    }

    fn as_slice<'a>(&'a self) -> &'a [u8] {
        unsafe {
            core::slice::from_raw_parts(
                (self as *const Header) as *const u8,
                std::mem::size_of::<Header>(),
            )
        }
    }
}

#[repr(u8)]
enum MessageType {
    /// Broadcast to locate available servers.
    Discover = 1u8.swap_bytes(),
    /// Message to servers to either:
    /// 1. Request the offered parameters from one server and implicitly
    ///    declining offers from all others.
    /// 2. Confirm correctness of previously allocated address after,
    ///    (e.g., system reboot).
    /// 3. Extend the lease on a particular network address.
    Request = 3u8.swap_bytes(),
}

#[repr(u8)]
enum DhcpOption {
    HostName = 12,
    RequestedIp = 50,
    MessageType = 53,
    ParameterRequestList = 55,
    ClientIdentifier = 61,
    End = 255,
}

struct OptionsWriter<'a>(&'a mut [u8]);

impl<'a> OptionsWriter<'a> {
    fn new(options: &'a mut [u8]) -> Self {
        options.fill(0);
        Self(options).set_magic_cookie()
    }

    fn insert(&mut self, kind: DhcpOption, data: &'_ [u8]) {
        let total_len = 2 + data.len();

        assert!(data.len() < u8::MAX as _);
        assert!(self.0.len() > total_len);

        let (buf, rest) = core::mem::take(&mut self.0).split_at_mut(total_len);
        self.0 = rest;

        buf[0] = kind as u8;
        buf[1] = data.len() as _;
        buf[2..].copy_from_slice(data);
    }

    fn insert_padding(&mut self, size: usize) {
        let (buf, rest) = core::mem::take(&mut self.0).split_at_mut(size);
        self.0 = rest;

        buf.fill(0);
    }

    fn set_magic_cookie(mut self) -> Self {
        let (buf, rest) = core::mem::take(&mut self.0).split_at_mut(core::mem::size_of::<u32>());

        // The first four octets of the 'options' field of the DHCP message
        // contain the (decimal) values 99, 130, 83 and 99, respectively.
        //
        // CC: (https://www.rfc-editor.org/rfc/rfc2131#section-3)
        NetworkEndian::write_u32(buf, 0x63825363);
        self.0 = rest;
        self
    }

    fn set_message_type(mut self, typ: MessageType) -> Self {
        self.insert(DhcpOption::MessageType, &[typ as u8]);
        self
    }

    fn set_parameter_request_list(mut self) -> Self {
        // TODO: Take all of the request flags as an argument.
        self.insert(
            DhcpOption::ParameterRequestList,
            &[
                1,  // Subnet Mask
                3,  // Router
                15, // Domain Name
                6,  // Domain Server
            ],
        );
        self
    }

    fn set_client_identifier(mut self) -> Self {
        let mut data = [0; 7];
        data[0] = HType::Ethernet as u8;
        data[1..].copy_from_slice(MAC_ADDRESS);

        self.insert(DhcpOption::ClientIdentifier, data.as_slice());
        self
    }

    fn set_host_name(mut self, name: &str) -> Self {
        self.insert(DhcpOption::HostName, name.as_bytes());
        self.insert_padding(1); // null-terminator
        self
    }

    fn set_requested_ip(mut self, ip: Ipv4Addr) -> Self {
        self.insert(DhcpOption::RequestedIp, &ip.0);
        self
    }
}

impl<'a> Drop for OptionsWriter<'a> {
    fn drop(&mut self) {
        self.insert(DhcpOption::End, &[]);
    }
}

pub fn main() -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind(("0.0.0.0", 68))?;
    socket.connect(("255.255.255.255", 67))?;

    let mut discover_header = Header::new(HType::Ethernet);
    discover_header
        .options_mut()
        .set_message_type(MessageType::Discover)
        .set_client_identifier()
        .set_host_name("Aero")
        .set_parameter_request_list();

    socket.send(discover_header.as_slice())?;

    let mut offer_bytes = [0u8; core::mem::size_of::<Header>()];
    socket.recv(&mut offer_bytes)?;

    // SAFETY: The array has the same size as of the DHCP header.
    let offer = unsafe { &*(offer_bytes.as_ptr() as *const Header) };
    println!("dhcpd: recieved offer {:?}", offer.your_ip);

    let mut request_header = Header::new(HType::Ethernet);
    request_header
        .options_mut()
        .set_message_type(MessageType::Request)
        .set_client_identifier()
        .set_requested_ip(offer.your_ip)
        .set_host_name("Aero")
        .set_parameter_request_list();

    socket.send(request_header.as_slice())?;

    Ok(())
}
