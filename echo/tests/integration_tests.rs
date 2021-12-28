use core::time;
use std::convert::TryFrom;

use assert_cmd::{Command, cargo::cargo_bin};
use kernel_tracer::kernel_tracer_client::KernelTracerClient;
use tokio::net::UnixStream;
use tonic::transport;
use tower::service_fn;

const PROG_NAME: &str = "echo";
const SOCKET_PATH: &str = "/tmp/test.sock";

pub mod kernel_tracer {
    tonic::include_proto!("kernel_tracer");
}

#[test]
fn check_default() {
    let mut cmd = Command::cargo_bin(PROG_NAME).unwrap();
    cmd.assert().failure();
}

macro_rules! aw {
    ($e:expr) => {
        tokio_test::block_on($e)
    };
}

fn am_root() -> bool {
    match std::env::var("USER") {
        Ok(val) => val == "root",
        Err(_) => false,
    }

}

#[test]
fn check_metrics() {

    if !am_root() {
        println!("Not root, skipping test");
        return;
    }

    let mut cmd = std::process::Command::new(cargo_bin(PROG_NAME).to_str().unwrap());
    cmd.args(["--socket-path", SOCKET_PATH]).spawn().unwrap();

    std::thread::sleep(time::Duration::from_secs(2));
    let channel = aw!(transport::Endpoint::try_from("http://[::]:50051").unwrap().
        connect_with_connector(service_fn(|_: transport::Uri| {
            UnixStream::connect(SOCKET_PATH)
        }))).unwrap();

    let mut client = KernelTracerClient::new(channel);
    let request = tonic::Request::new(kernel_tracer::Empty {});
    let response = aw!(client.get_metrics(request)).unwrap();

    let response = response.into_inner();
    assert!(response.event_failure_count == 0, "Have failures");
    assert!(response.event_success_count > 0, "No success");
}
