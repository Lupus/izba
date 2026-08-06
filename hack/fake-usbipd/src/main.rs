//! A usbip server exporting one CDC-ACM device that echoes.
//!
//! This exists so izba's USB datapath can be tested against a real guest
//! kernel. Everything else in the feature is unit-tested against byte-level
//! fakes, but nothing hand-written can stand in for what `vhci-hcd` and
//! `cdc-acm` actually do: enumerate the device with a series of control
//! transfers, bind a driver to it, and create a tty. That requires a server
//! with full device fidelity, which is what `jiegec/usbip` provides.
//!
//! The device echoes: whatever is written to its bulk-OUT endpoint comes back
//! on bulk-IN. That makes the end-to-end assertion behavioural — write to
//! `/dev/izba/ttyACM0` inside the sandbox and read the same bytes back — which
//! can only pass if URBs really flowed guest vhci → vsock 1028 → izbad → TCP →
//! here, and all the way back.
//!
//! Usage: `fake-usbipd [BIND_ADDR]` (default `127.0.0.1:0`). It prints the
//! address it actually bound on stdout, so a test can take an ephemeral port
//! instead of racing for 3240.

use std::any::Any;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use usbip::{
    ClassCode, Direction, EndpointAttributes, SetupPacket, UsbDevice, UsbEndpoint, UsbInterface,
    UsbInterfaceHandler, UsbIpServer,
};

/// The device izba's tests grant. An FTDI id, because that is what a human
/// plugging in a dev board is most likely to be looking at.
const VENDOR_ID: u16 = 0x0403;
const PRODUCT_ID: u16 = 0x6001;

/// A CDC-ACM interface whose bulk-IN returns whatever bulk-OUT was given.
///
/// `usbip::cdc::UsbCdcAcmHandler` discards writes and serves a buffer the
/// application fills, which would let a test pass while proving only that the
/// guest→host direction reached *something*. Echoing ties the two directions
/// together: the bytes that come back are the bytes that went out.
#[derive(Debug, Default)]
struct EchoAcmHandler {
    pending: Vec<u8>,
}

impl UsbInterfaceHandler for EchoAcmHandler {
    fn handle_urb(
        &mut self,
        _interface: &UsbInterface,
        ep: UsbEndpoint,
        _transfer_buffer_length: u32,
        _setup: SetupPacket,
        req: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        // The interrupt endpoint carries CDC state notifications; the guest's
        // cdc-acm driver polls it and is content with nothing to report.
        if ep.attributes == EndpointAttributes::Interrupt as u8 {
            return Ok(vec![]);
        }
        match ep.direction() {
            Direction::Out => {
                self.pending.extend_from_slice(req);
                Ok(vec![])
            }
            Direction::In => {
                // Answer with at most one packet, as real hardware would; the
                // guest reads again for the rest.
                let n = self.pending.len().min(ep.max_packet_size as usize);
                Ok(self.pending.drain(..n).collect())
            }
        }
    }

    /// The CDC functional descriptors the host's cdc-acm driver expects between
    /// the interface and endpoint descriptors. Without them the driver does not
    /// recognise the interface and no tty is created.
    fn get_class_specific_descriptor(&self) -> Vec<u8> {
        vec![
            // Header functional descriptor: CDC 1.2.
            0x05, 0x24, 0x00, 0x10, 0x01, //
            // ACM functional descriptor, no optional capabilities.
            0x04, 0x24, 0x02, 0x00,
        ]
    }

    fn as_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[tokio::main]
async fn main() {
    let bind: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:0".to_string())
        .parse()
        .expect("BIND_ADDR must be host:port");

    let handler = Arc::new(Mutex::new(
        Box::new(EchoAcmHandler::default()) as Box<dyn UsbInterfaceHandler + Send>
    ));
    let mut device = UsbDevice::new(0).with_interface(
        ClassCode::CDC as u8,
        usbip::cdc::CDC_ACM_SUBCLASS,
        0x00,
        Some("izba fake serial"),
        usbip::cdc::UsbCdcAcmHandler::endpoints(),
        handler,
    );
    // The ids izba's grant names. `UsbDevice::new` picks placeholders; the
    // whole point of the test is that the allow-list matched THIS device.
    device.vendor_id = VENDOR_ID;
    device.product_id = PRODUCT_ID;

    let server = Arc::new(UsbIpServer::new_simulated(vec![device]));
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .expect("bind the fake usbip server");
    let addr = listener.local_addr().expect("local addr");

    // Announce the real address before serving: with port 0 the caller cannot
    // know it any other way, and flushing matters because the test reads this
    // line to decide the server is up.
    println!("{addr}");
    std::io::stdout().flush().ok();

    loop {
        let Ok((socket, _peer)) = listener.accept().await else {
            continue;
        };
        let server = server.clone();
        tokio::spawn(async move {
            let mut socket = socket;
            usbip::handler(&mut socket, server).await.ok();
        });
    }
}
