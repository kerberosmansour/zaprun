use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

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
