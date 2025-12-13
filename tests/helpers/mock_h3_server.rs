use quiche::ConnectionId;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

// Self-signed certificate for testing
const CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIICWjCCAcKgAwIBAgIBAzANBgkqhkiG9w0BAQsFADAoMSYwJAYDVQQDDB1xdWlj
aGUgc2VsZi1zaWduZWQgY2VydGlmaWNhdGUwHhcNMjAwMTAxMDAwMDAwWhcNMzAw
MTAxMDAwMDAwWjAoMSYwJAYDVQQDDB1xdWljaGUgc2VsZi1zaWduZWQgY2VydGlm
aWNhdGUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9C6aAm2j7TCLr
E/2N+t2tZFxByJg+gN+XfP6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X
6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q
/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z
7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X
6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q
/0CAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAq7KkS8qjgJz7Q/X6Z7Q/X6Z7Q/X6Z
7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X
6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q
/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z
7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X
6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q/X6Z7Q
/0==
-----END CERTIFICATE-----";
// Note: This is a dummy cert. In a real scenario we'd use a properly generated one.
// For the sake of this mock, we will generate a fresh one at runtime using a helper
// or just trust that quiche's validation can be disabled or configured to accept this.
// Actually, simpler: write temp files.

/// A mock HTTP/3 server for testing.
pub struct MockH3Server {
    socket: Arc<UdpSocket>,
    port: u16,
    cert_path: String,
    key_path: String,
}

impl MockH3Server {
    pub async fn new() -> std::io::Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let port = socket.local_addr()?.port();
        let socket = Arc::new(socket);

        // precise frame control requires handling the connection manually

        // Write cert/key to temp files
        let cert_path = std::env::temp_dir().join(format!("mock_h3_{}.crt", port));
        let key_path = std::env::temp_dir().join(format!("mock_h3_{}.key", port));

        let _ = std::process::Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path.to_str().unwrap(),
                "-out",
                cert_path.to_str().unwrap(),
                "-days",
                "365",
                "-nodes",
                "-subj",
                "/CN=localhost",
            ])
            .output()?;

        Ok(Self {
            socket,
            port,
            cert_path: cert_path.to_str().unwrap().to_string(),
            key_path: key_path.to_str().unwrap().to_string(),
        })
    }

    pub fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    pub fn start<F, Fut>(self, handler: F) -> tokio::task::JoinHandle<()>
    where
        F: Fn(MockH3Connection) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        tokio::spawn(async move {
            self.run(handler).await;
        })
    }

    async fn run<F, Fut>(&self, handler: F)
    where
        F: Fn(MockH3Connection) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send,
    {
        let mut buf = [0u8; 65535];
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file(&self.cert_path)
            .unwrap();
        config.load_priv_key_from_pem_file(&self.key_path).unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_max_idle_timeout(5000);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);

        config.set_disable_active_migration(true);

        // Ring usage removed (unused)

        let mut connections: HashMap<ConnectionId<'static>, mpsc::Sender<(Vec<u8>, SocketAddr)>> =
            HashMap::new();
        let socket = self.socket.clone();
        // Need local addr for accept
        let local_addr = socket.local_addr().unwrap();

        let handler = Arc::new(handler);

        // Clone paths for task
        let cert_path = self.cert_path.clone();
        let key_path = self.key_path.clone();

        loop {
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("UDP recv error: {}", e);
                    break;
                }
            };
            let packet = buf[..len].to_vec();

            let header = match quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN)
            {
                Ok(h) => h,
                Err(_) => continue, // Invalid packet
            };

            let conn_id = header.dcid.clone();

            // If new connection
            if !connections.contains_key(&conn_id) {
                if header.ty != quiche::Type::Initial {
                    continue; // Must start with Initial
                }

                if !quiche::version_is_supported(header.version) {
                    // Version negotiation?
                    continue;
                }

                // Actually need to clone it to static
                let scid = header.dcid.into_owned();

                let (tx, mut rx) = mpsc::channel(100);
                connections.insert(scid.clone(), tx.clone());

                // Spawn connection handler
                let socket_clone = socket.clone();
                let mut config_clone = match quiche::Config::new(quiche::PROTOCOL_VERSION) {
                    Ok(c) => c,
                    Err(_) => continue,
                };

                config_clone
                    .load_cert_chain_from_pem_file(&cert_path)
                    .unwrap();
                config_clone.load_priv_key_from_pem_file(&key_path).unwrap();
                config_clone.set_application_protos(&[b"h3"]).unwrap();
                config_clone.set_max_idle_timeout(30_000);
                config_clone.set_max_recv_udp_payload_size(65535);
                config_clone.set_max_send_udp_payload_size(1350);
                config_clone.set_initial_max_data(15_663_105);
                config_clone.set_initial_max_stream_data_bidi_local(1_000_000);
                config_clone.set_initial_max_stream_data_bidi_remote(1_000_000);
                config_clone.set_initial_max_stream_data_uni(1_000_000);
                config_clone.set_initial_max_streams_bidi(100);
                config_clone.set_initial_max_streams_uni(100);
                config_clone.set_disable_active_migration(true);

                let handler_clone = handler.clone();
                let scid_clone = scid.clone();
                let odcid = scid.clone();

                let cert_path_clone = cert_path.clone();
                let key_path_clone = key_path.clone();

                tokio::spawn(async move {
                    // Create configuration for this connection
                    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
                    if let Err(e) = config.load_cert_chain_from_pem_file(&cert_path_clone) {
                        tracing::error!("MockServer: Failed to load cert: {}", e);
                        return;
                    }
                    if let Err(e) = config.load_priv_key_from_pem_file(&key_path_clone) {
                        tracing::error!("MockServer: Failed to load key: {}", e);
                        return;
                    }
                    config.set_application_protos(&[b"h3"]).unwrap();
                    config.set_max_idle_timeout(30_000);
                    config.set_max_recv_udp_payload_size(65535);
                    config.set_max_send_udp_payload_size(1350);
                    config.set_initial_max_data(15_663_105);
                    config.set_initial_max_stream_data_bidi_local(1_000_000);
                    config.set_initial_max_stream_data_bidi_remote(1_000_000);
                    config.set_initial_max_stream_data_uni(1_000_000);
                    config.set_initial_max_streams_bidi(100);
                    config.set_initial_max_streams_uni(100);
                    config.set_disable_active_migration(true);

                    let mut conn =
                        quiche::accept(&scid_clone, Some(&odcid), local_addr, peer, &mut config)
                            .unwrap();

                    // Create HTTP/3 connection context (Client will wait for Settings)
                    // Config unused for now as we don't init h3 connection
                    let _h3_config = quiche::h3::Config::new().unwrap();
                    let mut h3_conn: Option<quiche::h3::Connection> = None;

                    let (cmd_tx, mut cmd_rx) = mpsc::channel(100);
                    let (evt_tx, evt_rx) = mpsc::channel(100);

                    let mock_conn = MockH3Connection {
                        cmd_tx,
                        evt_rx: Arc::new(Mutex::new(evt_rx)),
                    };

                    tokio::spawn(async move {
                        handler_clone(mock_conn).await;
                    });

                    let mut out = [0u8; 65535];

                    let mut interval = tokio::time::interval(std::time::Duration::from_millis(10));

                    loop {
                        tokio::select! {
                            res = rx.recv() => {
                                match res {
                                    Some((packet, from)) => {
                                        let recv_info = quiche::RecvInfo {
                                            to: socket_clone.local_addr().unwrap(),
                                            from,
                                        };
                                        match conn.recv(&mut packet.clone(), recv_info) {
                                            Ok(_) => {
                                                if conn.is_established() {
                                                    if let Some(h3) = h3_conn.as_mut() {
                                                        loop {
                                                            match h3.poll(&mut conn) {
                                                                Ok((stream_id, quiche::h3::Event::Data)) => {
                                                                    // We need to read the data manually or via h3?
                                                                    // MockH3Server exposes RAW bytes usually.
                                                                    // But if we use h3, we get decrypted h3 frames?
                                                                    // Ideally, h3.poll() handles framing.
                                                                    // But we want to simulate SERVER behavior.
                                                                    // Let's use h3 just for handshake and settings.
                                                                    // If we receive data, forward event.
                                                                    let mut body = vec![0u8; 1024];
                                                                    if let Ok(n) = h3.recv_body(&mut conn, stream_id, &mut body) {
                                                                        let _ = evt_tx.send(MockEvent::Data { stream_id, data: body[..n].to_vec(), fin: false }).await;
                                                                    }
                                                                },
                                                                Ok((_stream_id, quiche::h3::Event::Headers { .. })) => {
                                                                     // Ignore headers for now or forward?
                                                                      let _ = evt_tx.send(MockEvent::Data { stream_id: _stream_id, data: b"HEADERS".to_vec(), fin: false }).await;
                                                                },
                                                                Err(quiche::h3::Error::Done) => break,
                                                                Err(_) => break,
                                                                _ => {}
                                                            }
                                                        }
                                                    }
                                                }
                                            },
                                            Err(e) => tracing::debug!("quiche recv error: {}", e),
                                        }
                                    },
                                    None => break,
                                }
                            }

                            _ = interval.tick() => {
                                conn.on_timeout();
                            }

                            cmd = cmd_rx.recv() => {
                                match cmd {
                                    Some(MockCommand::SendFrame { stream_id, payload }) => {
                                        let _ = conn.stream_send(stream_id, &payload, false);
                                    }
                                    Some(MockCommand::SendBytes { stream_id, bytes }) => {
                                         let _ = conn.stream_send(stream_id, &bytes, false);
                                    }
                                    None => {
                                        let _ = conn.close(true, 0x00, b"done");
                                    },
                                }
                            }
                        }

                        while let Ok((len, send_info)) = conn.send(&mut out) {
                            let _ = socket_clone.send_to(&out[..len], send_info.to).await;
                        }

                        if conn.is_closed() {
                            break;
                        }
                    }
                });
            }

            if let Some(tx) = connections.get(&conn_id) {
                let _ = tx.send((packet, peer)).await;
            }
        }
    }
}

enum MockCommand {
    SendFrame { stream_id: u64, payload: Vec<u8> },
    SendBytes { stream_id: u64, bytes: Vec<u8> },
}

#[derive(Debug)]
pub enum MockEvent {
    Data {
        stream_id: u64,
        data: Vec<u8>,
        fin: bool,
    },
}

pub struct MockH3Connection {
    cmd_tx: mpsc::Sender<MockCommand>,
    evt_rx: Arc<Mutex<mpsc::Receiver<MockEvent>>>,
}

impl MockH3Connection {
    /// Send raw bytes to a stream (allows sending headers or malformed frames manually)
    pub async fn send_bytes(&self, stream_id: u64, bytes: &[u8]) {
        let _ = self
            .cmd_tx
            .send(MockCommand::SendBytes {
                stream_id,
                bytes: bytes.to_vec(),
            })
            .await;
    }

    /// Helper to construct and send a simple frame
    pub async fn send_frame(&self, stream_id: u64, frame_type: u64, payload: &[u8]) {
        let mut buf = Vec::new();
        // Encode Type (VarInt)
        encode_varint(&mut buf, frame_type);
        // Encode Length (VarInt)
        encode_varint(&mut buf, payload.len() as u64);
        // Payload
        buf.extend_from_slice(payload);

        self.send_bytes(stream_id, &buf).await;
    }

    /// Read next event from the connection
    pub async fn read_event(&self) -> Option<MockEvent> {
        let mut rx = self.evt_rx.lock().await;
        rx.recv().await
    }
}

fn encode_varint(buf: &mut Vec<u8>, val: u64) {
    if val <= 63 {
        buf.push(val as u8);
    } else if val <= 16383 {
        let bytes = (val as u16 | 0x4000).to_be_bytes();
        buf.extend_from_slice(&bytes);
    } else if val <= 1073741823 {
        let bytes = (val as u32 | 0x80000000).to_be_bytes();
        buf.extend_from_slice(&bytes);
    } else {
        let bytes = (val | 0xC000000000000000).to_be_bytes();
        buf.extend_from_slice(&bytes);
    }
}
