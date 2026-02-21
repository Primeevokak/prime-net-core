use std::ffi::CString;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::ptr;
use std::thread;
use std::time::Duration;

use prime_net_engine_core::ffi::{
    prime_engine_fetch_async, prime_engine_free, prime_engine_new, prime_request_cancel,
    prime_request_status, prime_request_wait, prime_response_free, PrimeRequest,
    PrimeRequestStatus,
};

fn start_slow_http_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            thread::sleep(Duration::from_secs(10));
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
        }
    });
    port
}

#[test]
fn ffi_concurrent_cancellation_is_thread_safe() {
    let port = start_slow_http_server();
    let url = CString::new(format!("http://127.0.0.1:{port}/slow")).unwrap();
    let method = CString::new("GET").unwrap();

    let engine = prime_engine_new(ptr::null());
    assert!(!engine.is_null(), "engine must be created");

    let req = PrimeRequest {
        url: url.as_ptr(),
        method: method.as_ptr(),
        headers: ptr::null(),
        headers_count: 0,
        body: ptr::null(),
        body_len: 0,
    };

    let handle = unsafe { prime_engine_fetch_async(engine, &req, None, ptr::null_mut()) };
    assert!(!handle.is_null(), "async handle must be created");

    let handle_addr = handle as usize;
    let mut threads = Vec::new();
    for _ in 0..16 {
        threads.push(thread::spawn(move || {
            let handle = handle_addr as *mut _;
            for _ in 0..200 {
                let _ = unsafe { prime_request_cancel(handle) };
            }
        }));
    }
    for t in threads {
        t.join().unwrap();
    }

    let st = unsafe { prime_request_status(handle) };
    assert!(
        st == PrimeRequestStatus::CANCELLED || st == PrimeRequestStatus::COMPLETED,
        "unexpected status: {st:?}"
    );

    let resp = unsafe { prime_request_wait(handle, 5000) };
    assert!(!resp.is_null(), "wait must return a response");
    unsafe { prime_response_free(resp) };

    unsafe { prime_engine_free(engine) };
}
