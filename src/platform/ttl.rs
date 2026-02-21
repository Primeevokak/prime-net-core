use tokio::net::TcpStream;

#[cfg(windows)]
pub fn set_socket_ttl_low(socket: &TcpStream, ttl: u8) -> std::io::Result<()> {
    if ttl == 0 {
        return Ok(());
    }
    socket.set_ttl(ttl as u32)
}

#[cfg(not(windows))]
pub fn set_socket_ttl_low(_socket: &TcpStream, _ttl: u8) -> std::io::Result<()> {
    Ok(())
}
