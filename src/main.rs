// Dynamic Host Configuration Protocol

#[macro_use]
extern crate num_derive;

use num_traits::FromPrimitive;

use spin::Once;
use std::{error::Error, fmt::Display, io, net::UdpSocket};

use byteorder::{ByteOrder, NetworkEndian};
use simple_endian::BigEndian;

/// Size of IPv4 adderess in octets.
///
/// [RFC 8200 § 2]: https://www.rfc-editor.org/rfc/rfc791#section-3.2
pub const ADDR_SIZE: usize = 4;

pub const DHCP_SERVER_PORT: u16 = 67;
pub const DHCP_CLIENT_PORT: u16 = 68;

#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Default)]
pub struct Ipv4Addr(pub [u8; ADDR_SIZE]);

impl Ipv4Addr {
    const EMPTY: Self = Self([0; ADDR_SIZE]);

    fn as_u32(&self) -> u32 {
        byteorder::BigEndian::read_u32(&self.0)
    }
}

impl From<libc::in_addr> for Ipv4Addr {
    fn from(value: libc::in_addr) -> Self {
        Self(value.s_addr.to_be_bytes())
    }
}

impl Display for Ipv4Addr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "{}.{}.{}.{}",
            self.0[0], self.0[1], self.0[2], self.0[3]
        ))?;

        Ok(())
    }
}

const DHCP_XID: u32 = 0x43424140;

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
enum DhcpType {
    BootRequest = 1u8.swap_bytes(),
    BootReply = 2u8.swap_bytes(),
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u8)]
enum HType {
    Ethernet = 1u8.swap_bytes(),
}

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
        client_hw_addr[0..6].copy_from_slice(get_macaddress());

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

    fn options(&self) -> OptionsIter<'_> {
        OptionsIter::new(&self.options)
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

    fn as_slice_mut<'a>(&'a mut self) -> &'a mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                (self as *mut Header) as *mut u8,
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

#[derive(FromPrimitive, Debug, PartialEq)]
#[repr(u8)]
enum OptionKind {
    // Vendor Extensions
    End = 255,
    Pad = 0,
    SubnetMask = 1,
    TimeOffset = 2,
    Router = 3,
    TimeServer = 4,
    NameServer = 5,
    DomainNameServer = 6,
    LogServer = 7,
    CookieServer = 8,
    LprServer = 9,
    ImpressServer = 10,
    ResourceLocationServer = 11,
    HostName = 12,
    BootFileSize = 13,
    MeritDump = 14,
    DomainName = 15,
    SwapServer = 16,
    RootPath = 17,
    ExtensionsPath = 18,

    // IP Layer Parameters per Host
    IpForwarding = 19,
    NonLocalSourceRouting = 20,
    PolicyFilter = 21,
    MaxDatagramReassemblySize = 22,
    DefaultTtl = 23,
    PathMtuAgingTimeout = 24,
    PathMtuPlateuTable = 25,

    // IP Layer Parameters per Interface
    InterfaceMtu = 26,
    AllSubnetsAreLocal = 27,
    BroadcastAddress = 28,
    PerformMaskDiscovery = 29,
    MaskSupplier = 30,
    PerformRouterDiscovery = 31,
    RouterSolicitationAddress = 32,
    StaticRoute = 33,

    // Link Layer Parameters per Interface
    TrailerEncapsulation = 34,
    ArpCacheTimeout = 35,
    EthernetEncapsulation = 36,

    // TCP Parameters
    TcpDefaultTtl = 37,
    TcpKeepaliveInterval = 38,
    TcpKeepaliveGarbage = 39,

    // Application and Service Parameters
    NisDomain = 40,
    NisServers = 41,
    NtpServers = 42,
    VendorSpecificInfo = 43,
    NetbiosNameServer = 44,
    NetbiosDistributionServer = 45,
    NetbiosNodeType = 46,
    NetbiosScope = 47,
    XWindowFontServer = 48,
    XWindowDisplayManager = 49,
    NisPlusDomain = 64,
    NisPlusServers = 65,
    MobileIpHomeAgent = 68,
    SmtpServer = 69,
    Pop3Server = 70,
    NntpServer = 71,
    WwwServer = 72,
    FingerServer = 73,
    IrcServer = 74,
    StreettalkServer = 75,
    StdaServer = 76,

    // DHCP Extensions
    RequestedIp = 50,
    IpLeaseTime = 51,
    OptionOverload = 52,
    TftpServerName = 66,
    BootfileName = 67,
    MessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    Message = 56,
    MaxDhcpMessageSize = 57,
    RenewalTimeValue = 58,
    RebindingTimeValue = 59,
    VendorClassId = 60,
    ClientIdentifier = 61,
}

struct OptionsIter<'a> {
    options: &'a [u8],
    index: usize,
}

impl<'a> OptionsIter<'a> {
    fn new(options: &'a [u8]) -> Self {
        Self {
            // Skip the first 4 bytes which contain the magic cookie.
            options: &options[4..],
            index: 0,
        }
    }
}

impl<'a> Iterator for OptionsIter<'a> {
    type Item = (OptionKind, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let kind =
            OptionKind::from_u8(self.options[self.index + 0]).expect("dhcpd: invalid option type");

        if kind == OptionKind::End {
            return None;
        }

        let len = self.options[self.index + 1] as usize;
        let data = &self.options[self.index + 2..self.index + 2 + len];

        self.index += 2 + len;
        Some((kind, data))
    }
}

struct OptionsWriter<'a>(&'a mut [u8]);

impl<'a> OptionsWriter<'a> {
    fn new(options: &'a mut [u8]) -> Self {
        options.fill(0);
        Self(options).set_magic_cookie()
    }

    fn insert(&mut self, kind: OptionKind, data: &'_ [u8]) {
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
        self.insert(OptionKind::MessageType, &[typ as u8]);
        self
    }

    fn set_parameter_request_list(mut self) -> Self {
        // TODO: Take all of the request flags as an argument.
        self.insert(
            OptionKind::ParameterRequestList,
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
        data[1..].copy_from_slice(get_macaddress());

        self.insert(OptionKind::ClientIdentifier, data.as_slice());
        self
    }

    fn set_host_name(mut self, name: &str) -> Self {
        self.insert(OptionKind::HostName, name.as_bytes());
        self.insert_padding(1); // null-terminator
        self
    }

    fn set_requested_ip(mut self, ip: Ipv4Addr) -> Self {
        self.insert(OptionKind::RequestedIp, &ip.0);
        self
    }
}

impl<'a> Drop for OptionsWriter<'a> {
    fn drop(&mut self) {
        self.insert(OptionKind::End, &[]);
    }
}

pub fn cvt(t: i32) -> io::Result<i32> {
    if t == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(t)
    }
}

fn get_nicname<'a>() -> &'a str {
    static CACHED: Once<String> = Once::new();

    CACHED.call_once(|| {
        let nic_name = std::env::args().nth(1).unwrap_or(DEFAULT_NIC.to_string());

        get_index(&nic_name)
            .unwrap_or_else(|nic_name| panic!("[ DHCPD ] (EE) invalid NIC name {}", nic_name));

        nic_name
    })
}

fn get_macaddress<'a>() -> &'a [u8; 6] {
    static CACHED: Once<[u8; 6]> = Once::new();
    CACHED
        .try_call_once(|| unsafe {
            let fd = cvt(libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0))?;

            let macaddr = IfReq::new(get_nicname());
            cvt(libc::ioctl(fd, libc::SIOCGIFHWADDR, &macaddr))?;

            Ok::<[u8; 6], io::Error>(macaddr.macaddr())
        })
        // FIXME: Should we panic here?
        .expect("[ DHCPD ] (EE) failed to retrieve the mac address")
}

struct SockAddrIn(libc::sockaddr_in);

impl SockAddrIn {
    pub fn new(addr: Ipv4Addr) -> Self {
        let sin_addr = libc::in_addr {
            s_addr: addr.as_u32(),
        };

        Self(libc::sockaddr_in {
            sin_family: libc::AF_INET as _,
            sin_addr,

            ..unsafe { core::mem::zeroed() }
        })
    }
}

impl Into<libc::sockaddr> for SockAddrIn {
    fn into(self) -> libc::sockaddr {
        unsafe { core::mem::transmute_copy(&self.0) }
    }
}

struct IfReq(libc::ifreq);

impl IfReq {
    pub fn new(interface: &str) -> Self {
        let mut ifr: libc::ifreq = unsafe { core::mem::zeroed() };
        assert!(interface.len() <= libc::IFNAMSIZ);

        // SAFETY: We have verified above that the name will fit
        //         in the buffer.
        unsafe {
            core::ptr::copy_nonoverlapping(
                interface.as_ptr(),
                ifr.ifr_name.as_mut_ptr() as *mut u8,
                interface.len(),
            );
        }

        Self(ifr)
    }

    fn set_addr(mut self, ip: Ipv4Addr) -> libc::ifreq {
        self.0.ifr_ifru.ifru_addr = SockAddrIn::new(ip).into();
        self.0
    }

    unsafe fn macaddr(&self) -> [u8; 6] {
        let data: &[i8; 6] = &self.0.ifr_ifru.ifru_hwaddr.sa_data[..6]
            .try_into()
            .expect("macaddr: address validation failed");

        let data: [i8; 6] = data.clone();

        // SAFETY: The caller guarantees that union field we are accessing
        //         has been initialized with a mac address. With all of that,
        //         transmuting the data array into [u8; 6] is safe.
        core::mem::transmute(data)
    }
}

fn configure(interface: &str, ip: Ipv4Addr, subnet_mask: Ipv4Addr) -> io::Result<()> {
    let fd = cvt(unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) })?;

    let interface_addr = IfReq::new(interface).set_addr(ip);

    // Set the interface address.
    unsafe {
        cvt(libc::ioctl(fd, libc::SIOCSIFADDR, &interface_addr))?;
    }

    let subnet_mask = IfReq::new(interface).set_addr(subnet_mask);

    // Set the subnet mask.
    // unsafe {
    //     cvt(libc::ioctl(fd, libc::SIOCSIFNETMASK, &subnet_mask))?;
    // }

    Ok(())
}

const DEFAULT_NIC: &str = "eth0"; // FIXME: retrieve the default NIC from the kernel

fn get_index(nic: &str) -> io::Result<libc::c_uint> {
    let ifname = std::ffi::CString::new(nic)?;
    match unsafe { libc::if_nametoindex(ifname.as_ptr()) } {
        0 => Err(io::Error::last_os_error()),
        index => Ok(index),
    }
}

pub fn main() -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind(("0.0.0.0", DHCP_CLIENT_PORT))?;

    let mut discover_header = Header::new(HType::Ethernet);
    discover_header
        .options_mut()
        .set_message_type(MessageType::Discover)
        .set_client_identifier()
        .set_host_name("Aero")
        .set_parameter_request_list();

    socket.send_to(discover_header.as_slice(), "255.255.255.255:67")?;

    let mut offer = Header::new(HType::Ethernet);
    socket.recv(offer.as_slice_mut())?;

    assert!(offer.op == DhcpType::BootReply);

    let mut request_header = Header::new(HType::Ethernet);
    request_header
        .options_mut()
        .set_message_type(MessageType::Request)
        .set_client_identifier()
        .set_requested_ip(offer.your_ip)
        .set_host_name("Aero")
        .set_parameter_request_list();

    socket.send_to(request_header.as_slice(), "255.255.255.255:67")?;

    let mut ack = Header::new(HType::Ethernet);
    socket.recv(ack.as_slice_mut())?;

    assert!(ack.op == DhcpType::BootReply);

    let mut default_gateway = None;
    let mut subnet_mask = None;
    let mut dns = None;

    for (option, data) in ack.options() {
        match option {
            OptionKind::ServerIdentifier => default_gateway = Some(Ipv4Addr(data.try_into()?)),
            OptionKind::SubnetMask => subnet_mask = Some(Ipv4Addr(data.try_into()?)),
            OptionKind::DomainNameServer => dns = Some(Ipv4Addr(data.try_into()?)),
            _ => continue,
        }
    }

    let default_gateway = default_gateway.unwrap();
    let subnet_mask = subnet_mask.unwrap();
    let dns = dns.unwrap();

    configure(get_nicname(), ack.your_ip, subnet_mask)?;

    println!("[ DHCPD ] (!!) Configured:");
    println!("[ DHCPD ] (!!) IP:              {}", ack.your_ip);
    println!("[ DHCPD ] (!!) Default Gateway: {}", default_gateway);
    println!("[ DHCPD ] (!!) Subnet Mask:     {}", subnet_mask);
    println!("[ DHCPD ] (!!) DNS:             {}", dns);

    Ok(())
}
