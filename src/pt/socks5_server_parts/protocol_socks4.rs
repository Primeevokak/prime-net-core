#[allow(clippy::too_many_arguments)]
async fn handle_socks4(
    conn_id: u64,
    mut tcp: TcpStream,
    peer: SocketAddr,
    client: String,
    outbound: DynOutbound,
    cmd: u8,
    silent_drop: bool,
    relay_opts: RelayOptions,
) -> Result<()> {
    if !WARNED_SOCKS4_LIMITATIONS.swap(true, Ordering::Relaxed) {
        warn!(
            target: "socks5",
            "SOCKS4/4a clients detected: requests often use IP literals, reducing anti-censorship effectiveness (prefer SOCKS5/CONNECT clients when possible)"
        );
    }

    if cmd != 0x01 {
        warn!(target: "socks5", conn_id, peer = %peer, client = %client, cmd, "SOCKS4 unsupported command");
        if !silent_drop {
            let _ = tcp.write_all(&[0x00, 0x5b, 0, 0, 0, 0, 0, 0]).await;
        }
        let _ = tcp.shutdown().await;
        return Ok(());
    }

    let mut port_buf = [0u8; 2];
    tcp.read_exact(&mut port_buf).await?;
    let port = u16::from_be_bytes(port_buf);

    let mut ip_buf = [0u8; 4];
    tcp.read_exact(&mut ip_buf).await?;

    let _user_id = read_cstring(&mut tcp, 512).await?;

    let target_addr = if ip_buf[0] == 0 && ip_buf[1] == 0 && ip_buf[2] == 0 && ip_buf[3] != 0 {
        let host = read_cstring(&mut tcp, 2048).await?;
        if host.trim().is_empty() {
            warn!(target: "socks5", conn_id, peer = %peer, client = %client, "SOCKS4a empty host");
            if !silent_drop {
                let _ = tcp.write_all(&[0x00, 0x5b, 0, 0, 0, 0, 0, 0]).await;
            }
            let _ = tcp.shutdown().await;
            return Ok(());
        }
        TargetAddr::Domain(host)
    } else {
        TargetAddr::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip_buf)))
    };

    let destination = format_target(&target_addr, port);
    info!(target: "socks5", conn_id, peer = %peer, client = %client, destination = %destination, "SOCKS4 CONNECT requested");
    let mut out = match outbound
        .connect(TargetEndpoint {
            addr: target_addr,
            port,
        })
        .await
    {
        Ok(stream) => stream,
        Err(e) => {
            warn!(target: "socks5", conn_id, peer = %peer, client = %client, destination = %destination, error = %e, "SOCKS4 upstream failed");
            if !silent_drop {
                let _ = tcp.write_all(&[0x00, 0x5b, 0, 0, 0, 0, 0, 0]).await;
            }
            let _ = tcp.shutdown().await;
            return Ok(());
        }
    };

    if let Err(e) = tcp.write_all(&[0x00, 0x5a, 0, 0, 0, 0, 0, 0]).await {
        if is_expected_disconnect(&e) {
            info!(
                target: "socks5",
                conn_id,
                peer = %peer,
                client = %client,
                destination = %destination,
                error = %e,
                "SOCKS4 client disconnected before connect reply"
            );
            return Ok(());
        }
        return Err(e.into());
    }
    let tuned = tune_relay_for_target(relay_opts, port, &destination, true, false);
    match relay_bidirectional(&mut tcp, &mut out, tuned.options.clone()).await {
        Ok((bytes_client_to_upstream, bytes_upstream_to_client)) => {
            if should_skip_empty_session_scoring(bytes_client_to_upstream, bytes_upstream_to_client)
            {
                info!(
                    target: "socks5",
                    conn_id,
                    peer = %peer,
                    client = %client,
                    destination = %destination,
                    "SOCKS4 classifier update skipped for empty session"
                );
            } else if should_mark_suspicious_zero_reply(
                port,
                bytes_client_to_upstream,
                bytes_upstream_to_client,
                tuned.options.suspicious_zero_reply_min_c2u,
            ) {
                record_destination_failure(
                    &destination,
                    BlockingSignal::SuspiciousZeroReply,
                    tuned.options.classifier_emit_interval_secs,
                    tuned.stage,
                );
                warn!(
                    target: "socks5",
                    conn_id,
                    peer = %peer,
                    client = %client,
                    destination = %destination,
                    bytes_client_to_upstream,
                    bytes_upstream_to_client,
                    "SOCKS4 suspicious early close (no upstream bytes) classified as potential blocking"
                );
            } else {
                record_destination_success(&destination, tuned.stage, tuned.source);
            }
            info!(
                target: "socks5",
                conn_id,
                peer = %peer,
                client = %client,
                destination = %destination,
                bytes_client_to_upstream,
                bytes_upstream_to_client,
                "SOCKS4 session closed"
            );
        }
        Err(e) if is_expected_disconnect(&e) => {
            info!(
                target: "socks5",
                conn_id,
                peer = %peer,
                client = %client,
                destination = %destination,
                error = %e,
                "SOCKS4 relay closed by peer"
            );
        }
        Err(e) => {
            let signal = classify_io_error(&e);
            record_destination_failure(
                &destination,
                signal,
                tuned.options.classifier_emit_interval_secs,
                tuned.stage,
            );
            warn!(
                target: "socks5",
                conn_id,
                peer = %peer,
                client = %client,
                destination = %destination,
                error = %e,
                "SOCKS4 relay interrupted"
            );
        }
    }
    Ok(())
}
