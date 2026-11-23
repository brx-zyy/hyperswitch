//! Regression test for the proposed connection-time DNS rebinding defense.
//! All DNS and TCP endpoints are loopback-only. No internal network or metadata target is contacted.

use std::{
    io,
    net::{TcpListener, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use common_utils::{
    outbound_url::SafeOutboundUrl,
    request::{Method, Request},
};
use external_services::http_client::{outbound_destination::validate_destination, send_request};
use hyperswitch_interfaces::types::Proxy;

fn dns_reply(packet: &[u8], a_queries: &AtomicUsize) -> Vec<u8> {
    if packet.len() < 17 {
        return Vec::new();
    }
    let mut cursor = 12;
    let mut labels = Vec::new();
    while cursor < packet.len() && packet[cursor] != 0 {
        let len = packet[cursor] as usize;
        cursor += 1;
        if cursor + len > packet.len() {
            return Vec::new();
        }
        labels.push(String::from_utf8_lossy(&packet[cursor..cursor + len]).to_ascii_lowercase());
        cursor += len;
    }
    cursor += 1;
    if cursor + 4 > packet.len() {
        return Vec::new();
    }

    let name = labels.join(".");
    let qtype = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
    let question_end = cursor + 4;
    let answer_count: u16 = if qtype == 1 && name == "rebind.test" { 1 } else { 0 };

    let mut response = Vec::with_capacity(question_end + 32);
    response.extend_from_slice(&packet[0..2]);
    response.extend_from_slice(&[0x81, 0x80]);
    response.extend_from_slice(&[0, 1]);
    response.extend_from_slice(&answer_count.to_be_bytes());
    response.extend_from_slice(&[0, 0, 0, 0]);
    response.extend_from_slice(&packet[12..question_end]);

    if answer_count == 1 {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&[0, 1, 0, 1]);
        response.extend_from_slice(&[0, 0, 0, 0]);
        response.extend_from_slice(&[0, 4]);
        let address = if a_queries.fetch_add(1, Ordering::SeqCst) == 0 {
            [93, 184, 216, 34] // public documentation-range address during validation
        } else {
            [127, 0, 0, 1] // loopback during the actual connection-time lookup
        };
        response.extend_from_slice(&address);
    }
    response
}

fn start_dns_server() -> (Arc<AtomicBool>, thread::JoinHandle<()>, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind(("127.0.0.1", 53)).expect("bind isolated DNS server");
    socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let queries = Arc::new(AtomicUsize::new(0));
    let thread_running = Arc::clone(&running);
    let thread_queries = Arc::clone(&queries);
    let handle = thread::spawn(move || {
        let mut packet = [0u8; 1500];
        while thread_running.load(Ordering::SeqCst) {
            match socket.recv_from(&mut packet) {
                Ok((size, peer)) => {
                    let reply = dns_reply(&packet[..size], &thread_queries);
                    if !reply.is_empty() {
                        let _ = socket.send_to(&reply, peer);
                    }
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        || error.kind() == io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
    });
    (running, handle, queries)
}

#[tokio::test]
async fn connection_time_resolver_blocks_dns_rebinding_before_tcp_connect() {
    let (running, dns_thread, query_count) = start_dns_server();

    let sentinel = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback sentinel");
    sentinel.set_nonblocking(true).unwrap();
    let port = sentinel.local_addr().unwrap().port();

    let url = SafeOutboundUrl::from_url(
        url::Url::parse(&format!("http://rebind.test:{port}/probe")).unwrap(),
    )
    .unwrap();

    // Validation sees only the first, public answer and therefore accepts the URL.
    validate_destination(&url, None)
        .await
        .expect("public validation answer should be accepted");

    // The proposed Internet-scoped client resolves again at connection time. The DNS
    // server now returns loopback; the resolver must reject it before opening a TCP socket.
    let request = Request::new(Method::Get, url.get_string_repr());
    let result = send_request(&Proxy::default(), request, Some(5)).await;

    assert!(
        result.is_err(),
        "request must fail when the connection-time DNS answer is loopback"
    );
    assert!(
        query_count.load(Ordering::SeqCst) >= 2,
        "expected a distinct connection-time DNS lookup"
    );

    thread::sleep(Duration::from_millis(200));
    match sentinel.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Ok((_stream, peer)) => panic!("loopback sentinel received an outbound connection from {peer}"),
        Err(error) => panic!("unexpected sentinel accept error: {error}"),
    }

    running.store(false, Ordering::SeqCst);
    dns_thread.join().expect("join isolated DNS server");
}
