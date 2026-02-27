use tokio::net::TcpStream;

pub fn set_socket_ttl_low(socket: &TcpStream, ttl: u8) -> std::io::Result<()> {
    if ttl == 0 {
        return Ok(());
    }
    socket.set_ttl(ttl as u32)
}
