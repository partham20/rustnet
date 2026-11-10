//! Keeping tsr's own traffic off its tunnel.
//!
//! With an exit node, the OS sends all internet traffic into the tunnel,
//! including the connections tsr itself needs to carry that traffic: control,
//! DERP and the WireGuard/disco UDP socket. Like Tailscale, tsr pins those
//! sockets to the physical interface that holds the real default route
//! (`IP_UNICAST_IF` on Windows, `SO_BINDTOIFINDEX` on Linux), so they bypass
//! the tunnel's routes.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

/// Interface index to pin sockets to; 0 for none.
static INTERFACE: AtomicU32 = AtomicU32::new(0);
/// Bumped whenever [`INTERFACE`] changes, so long-lived sockets can re-pin.
static GENERATION: AtomicU32 = AtomicU32::new(0);

/// Pin new sockets to this interface index (0 turns pinning off).
pub fn set_interface(index: u32) {
    if INTERFACE.swap(index, Ordering::SeqCst) != index {
        GENERATION.fetch_add(1, Ordering::SeqCst);
        tracing::info!(
            interface = index,
            "tsr's own traffic now bypasses the tunnel via this interface"
        );
    }
}

pub fn interface() -> u32 {
    INTERFACE.load(Ordering::SeqCst)
}

pub fn generation() -> u32 {
    GENERATION.load(Ordering::SeqCst)
}

/// `TcpStream::connect`, but pinned to the bypass interface when one is set.
pub async fn tcp_connect(host: &str, port: u16) -> io::Result<TcpStream> {
    let index = interface();
    if index == 0 {
        return TcpStream::connect((host, port)).await;
    }
    let mut last = io::Error::new(io::ErrorKind::NotFound, format!("no address for {host}"));
    for addr in tokio::net::lookup_host((host, port)).await? {
        // Only IPv4 is routed into the tunnel, so IPv6 needs no pinning.
        let sock = match addr {
            SocketAddr::V4(_) => {
                let s = TcpSocket::new_v4()?;
                pin_v4(raw(&s), index)?;
                s
            }
            SocketAddr::V6(_) => TcpSocket::new_v6()?,
        };
        match sock.connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Pin an IPv4 UDP socket to the current bypass interface (or unpin it).
pub fn pin_udp(sock: &UdpSocket) -> io::Result<()> {
    pin_v4(raw(sock), interface())
}

#[cfg(windows)]
type Raw = std::os::windows::io::RawSocket;
#[cfg(unix)]
type Raw = std::os::fd::RawFd;

#[cfg(windows)]
fn raw<T: std::os::windows::io::AsRawSocket>(s: &T) -> Raw {
    s.as_raw_socket()
}
#[cfg(unix)]
fn raw<T: std::os::fd::AsRawFd>(s: &T) -> Raw {
    s.as_raw_fd()
}

#[cfg(windows)]
fn pin_v4(sock: Raw, index: u32) -> io::Result<()> {
    use windows_sys::Win32::Networking::WinSock::{
        setsockopt, WSAGetLastError, IPPROTO_IP, IP_UNICAST_IF, SOCKET_ERROR,
    };
    // For IPv4 the index goes in network byte order.
    let v = index.to_be();
    let r = unsafe {
        setsockopt(
            sock as _,
            IPPROTO_IP,
            IP_UNICAST_IF,
            &v as *const u32 as *const u8,
            4,
        )
    };
    if r == SOCKET_ERROR {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn pin_v4(sock: Raw, index: u32) -> io::Result<()> {
    let v = index as libc::c_int;
    let r = unsafe {
        libc::setsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_BINDTOIFINDEX,
            &v as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(windows, target_os = "linux")))]
fn pin_v4(_sock: Raw, index: u32) -> io::Result<()> {
    if index == 0 {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "socket pinning not supported on this OS",
    ))
}
