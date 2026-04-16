//! Serial transport layer for communicating with the ethapp service
//! on a Baochip-1x device over USB CDC-ACM.
//!
//! Wire protocol (framed over serial):
//!   Request:  [0xE7] [length: u16 LE] [opcode: u8] [payload...]
//!   Response: [0xE7] [length: u16 LE] [status: u8] [payload...]
//!
//! Magic byte 0xE7 is used for frame sync.
//! Length covers opcode/status + payload bytes.

use std::io::{Read, Write};
use std::time::Duration;

use anyhow::{bail, Context, Result};

const MAGIC: u8 = 0xE7;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
const BAUD_RATE: u32 = 115200;

/// USB Vendor/Product IDs for Baochip-1x (Precursor) device.
const VID: u16 = 0x1209;
const PID: u16 = 0x3613;

/// Status codes in responses.
pub const STATUS_OK: u8 = 0x00;

pub struct Transport {
    port: Box<dyn serialport::SerialPort>,
}

impl Transport {
    /// Open a connection to the device.
    ///
    /// If `path` is provided, use that serial port path directly.
    /// Otherwise, auto-detect the device by USB VID/PID.
    pub fn open(path: Option<&str>) -> Result<Self> {
        let port_name = match path {
            Some(p) => p.to_string(),
            None => auto_detect()?,
        };

        let port = serialport::new(&port_name, BAUD_RATE)
            .timeout(DEFAULT_TIMEOUT)
            .open()
            .with_context(|| format!("Failed to open serial port: {}", port_name))?;

        Ok(Self { port })
    }

    /// Send a command and receive a response.
    ///
    /// Returns (status, payload).
    pub fn command(&mut self, opcode: u8, payload: &[u8]) -> Result<(u8, Vec<u8>)> {
        self.send_frame(opcode, payload)?;
        self.receive_frame()
    }

    /// Send a framed request.
    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        let length = 1 + payload.len(); // opcode + payload
        if length > 0xFFFF {
            bail!("Payload too large: {} bytes", payload.len());
        }

        let mut frame = Vec::with_capacity(3 + length);
        frame.push(MAGIC);
        frame.extend_from_slice(&(length as u16).to_le_bytes());
        frame.push(opcode);
        frame.extend_from_slice(payload);

        self.port.write_all(&frame)?;
        self.port.flush()?;
        Ok(())
    }

    /// Receive a framed response.
    ///
    /// Returns (status, payload).
    fn receive_frame(&mut self) -> Result<(u8, Vec<u8>)> {
        // Read until we find the magic byte
        let mut byte = [0u8; 1];
        loop {
            self.port.read_exact(&mut byte)?;
            if byte[0] == MAGIC {
                break;
            }
        }

        // Read length (u16 LE)
        let mut len_buf = [0u8; 2];
        self.port.read_exact(&mut len_buf)?;
        let length = u16::from_le_bytes(len_buf) as usize;

        if length == 0 {
            bail!("Received empty frame");
        }

        // Read status + payload
        let mut data = vec![0u8; length];
        self.port.read_exact(&mut data)?;

        let status = data[0];
        let payload = data[1..].to_vec();

        Ok((status, payload))
    }
}

/// Auto-detect the Baochip-1x device by scanning serial ports.
fn auto_detect() -> Result<String> {
    let ports = serialport::available_ports()
        .context("Failed to enumerate serial ports")?;

    for port in &ports {
        if let serialport::SerialPortType::UsbPort(info) = &port.port_type {
            if info.vid == VID && info.pid == PID {
                return Ok(port.port_name.clone());
            }
        }
    }

    // If no VID/PID match, look for common ACM device names
    for port in &ports {
        if port.port_name.contains("ttyACM") || port.port_name.contains("cu.usbmodem") {
            return Ok(port.port_name.clone());
        }
    }

    bail!(
        "No Baochip-1x device found. Connect the device or specify --port.\n\
         Available ports: {:?}",
        ports.iter().map(|p| &p.port_name).collect::<Vec<_>>()
    )
}
