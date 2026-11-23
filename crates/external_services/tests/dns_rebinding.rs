//! Isolated regression test for DNS rebinding in outbound destination validation.
//! The test uses only a local DNS server and a local HTTP listener. It never contacts
//! public or cloud metadata services.

use std::{
    io::{Read, Write},
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

fn dns_reply(packet: &[u8], rebind_queries: &AtomicUsize) -> Vec<u8> {
    assert!(packet.len() >= 17, "short DNS query");
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

    let mut response = Vec::with_capacity(question_end + 32);
    response.extend_from_slice(&packet[0..2]); // transaction ID
    response.extend_from_slice(&[0x81, 0x80]); // standard response, recursion available
    response.extend_from_slice(&[0, 1]); // one question
    let answer_count = if qtype == 1 && (name == "rebind.test" || name == "private.test") { 1 } else { 0 };
    response.extend_from_slice(&(answer_count as u16).to_be_bytes());
    response.extend_from_slice(&[0, 0, 0, 0]); // authority and additional records
    response.extend_from_slice(&packet[12..question_end]);

    if answer_count == 1 {
        response.extend_from_slice(&[0xc0, 0x0c]); // compressed owner name
        response.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        response.extend_from_slice(&[0, 0, 0, 0]); // TTL 0
        response.extend_from_slice(&[0, 4]); // IPv4 length
        let address = if name == "private.test" {
            [127, 0, 0, 1]
        } else if rebind_queries.fetch_add(1, Ordering::SeqCst) == 0 {
            [93, 184, 216, 34] // public documentation-range test answer
        } else {
            [127, 0, 0, 1] // second answer: local-only test service
        };
        response.extend_from_slice(&address);
    }
    response
}

fn start_dns_server() -> (Arc<AtomicBool>, thread::JoinHandle<()>, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind(("127.0.0.1", 53)).expect("bind local test DNS on port 53");
    socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    let running = Arc::new(AtomicBool::new(true));
    let queries = Arc::new(AtomicUsize::new(0));
    let thread_running = Arc::clone(&running);
    let thread_queries = Arc::clone(&queries);
    let handle = thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while thread_running.load(Ordering::SeqCst) {
            match socket.recv_from(&mut buf) {
                Ok((size, peer)) => {
                    let reply = dns_reply(&buf[..size], &thread_queries);
                    if !reply.is_empty() {
                        let _ = socket.send_to(&reply, peer);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
    });
    (running, handle, queries)
}

#[tokio::test]
async fn dns_rebinding_is_checked_against_the_connection_destination() {
    let (running, dns_thread, query_count) = start_dns_server();

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind mock internal service");
    let port = listener.local_addr().unwrap().port();
    let http_thread = thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request);
            let body = b"INTERNAL_TEST_MARKER";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
        }
    });

    // First DNS answer is public, so validation should pass.
    let url = SafeOutboundUrl::from_url(
        url::Url::parse(&format!("http://rebind.test:{port}/probe")).unwrap(),
    )
    .unwrap();
    validate_destination(&url, None)
        .await
        .expect("first DNS answer should be accepted as public");

    // The production HTTP client resolves the same hostname again. The local DNS
    // server now returns 127.0.0.1. Reaching this listener proves the DNS check was
    // not bound to the actual outbound connection.
    let request = Request::new(Method::Get, url.get_string_repr());
    let response = send_request(&Proxy::default(), request, Some(5))
        .await
        .expect("outbound request should complete against the second DNS answer");
    let body = response.text().await.expect("read mock response");
    assert_eq!(body, "INTERNAL_TEST_MARKER");
    assert!(query_count.load(Ordering::SeqCst) >= 2, "expected separate DNS resolutions");

    // A host that resolves to loopback immediately must still be rejected.
    let private_url = SafeOutboundUrl::from_url(
        url::Url::parse(&format!("http://private.test:{port}/probe")).unwrap(),
    )
    .unwrap();
    assert!(
        validate_destination(&private_url, None).await.is_err(),
        "direct loopback DNS answer must be rejected"
    );

    running.store(false, Ordering::SeqCst);
    let _ = dns_thread.join();
    let _ = http_thread.join();
}
