use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[test]
fn observe_replays_raw_request_and_writes_response_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let request = temp.path().join("request.http");
    fs::write(
        &request,
        "GET /probe?name=slo HTTP/1.1\r\nHost: example.test\r\nX-Test: yes\r\n\r\n",
    )
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buffer = [0_u8; 1024];
        let read = stream.read(&mut buffer).unwrap();
        let request_text = String::from_utf8_lossy(&buffer[..read]);
        assert!(request_text.starts_with("GET /probe?name=slo "));
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 17\r\n\r\nobserved-response",
            )
            .unwrap();
    });

    let output = temp.path().join("out");
    Command::cargo_bin("zaprun")
        .unwrap()
        .arg("observe")
        .arg("--request")
        .arg(&request)
        .arg("--target")
        .arg(format!("http://{addr}"))
        .arg("--allow-internal-target")
        .arg("--output")
        .arg(&output)
        .assert()
        .success();
    server.join().unwrap();

    let observation: Value =
        serde_json::from_str(&fs::read_to_string(output.join("observations.json")).unwrap())
            .unwrap();
    assert_eq!(observation["schema_version"], "1.0");
    assert_eq!(observation["request_sent"], true);
    assert_eq!(observation["response_observed"], true);
    assert_eq!(observation["http_status"], 200);
    assert_eq!(observation["request_path"], "/probe?name=slo");
    assert_eq!(observation["decision_hint"], "http_observed");
    assert!(observation["response_body_hash"]
        .as_str()
        .unwrap()
        .starts_with("hash:"));
}

#[test]
fn observe_rejects_userinfo_loopback_before_replay() {
    let temp = tempfile::tempdir().unwrap();
    let request = temp.path().join("request.http");
    fs::write(&request, "GET /ssrf HTTP/1.1\r\nHost: example.test\r\n\r\n").unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok(_) => {
                    let _ = tx.send(true);
                    return;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        let _ = tx.send(false);
    });

    Command::cargo_bin("zaprun")
        .unwrap()
        .arg("observe")
        .arg("--request")
        .arg(&request)
        .arg("--target")
        .arg(format!("http://user@{addr}/base"))
        .arg("--output")
        .arg(temp.path().join("out"))
        .assert()
        .failure()
        .stderr(predicates::str::contains("private_net_blocked"));

    let connected = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    server.join().unwrap();
    assert!(!connected, "observe must reject before opening a socket");
}
