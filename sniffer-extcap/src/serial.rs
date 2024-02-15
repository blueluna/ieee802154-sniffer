use crate::Error;
use ieee802154_sniffer_wire_format as wire_format;
use std::time::Duration;
use std::io::{BufReader, BufRead};

pub(crate) struct DeviceSerial {
    port: Box<dyn serialport::SerialPort>,
    read_buffer: [u8; 4096],
    read_offset: usize,
}

impl DeviceSerial {
    pub(crate) fn open(name: &str) -> Result<Self, serialport::Error> {
        let mut port = serialport::new(name, 250_000)
            .timeout(Duration::from_millis(1))
            .open()?;
        let _ = port.clear(serialport::ClearBuffer::All);
        loop {
            if let Ok(len) = port.read(&mut [0u8; 128]) {
                if len == 0 {
                    break;
                }
            } else {
                break;
            }
        }
        Ok(DeviceSerial {
            port,
            read_buffer: [0u8; 4096],
            read_offset: 0,
        })
    }

    fn write_packet(&mut self, packet: &wire_format::Packet) -> Result<(), Error> {
        let mut buffer = [0u8; 256];
        let payload = packet.encode(&mut buffer)?;
        self.port.write_all(payload)?;
        Ok(())
    }

    fn read(&mut self) -> Result<(), Error> {
        let bytes = self.port.read(&mut self.read_buffer[self.read_offset..])?;
        self.read_offset += bytes;
        Ok(())
    }

    fn read_packet(&mut self) -> Result<Option<wire_format::Packet>, Error> {
        let mut work_buffer = [0u8; 4096];
        let end_marker = self.read_buffer[..self.read_offset].iter().position(|&b| b == 0x00);
        let end_marker = if end_marker == None {
            self.read()?;
            self.read_buffer[..self.read_offset].iter().position(|&b| b == 0x00)
        } else { end_marker };
        let frame_len = if let Some(end) = end_marker {
            end + 1
        } else { return Ok(None); };
        work_buffer[..frame_len].copy_from_slice(&self.read_buffer[..frame_len]);
        let work_frame = &mut work_buffer[..frame_len];
        let result = match wire_format::Packet::decode(work_frame) {
            Ok((packet, _)) => {
                Ok(Some(packet))
            }
            Err(e) => {
                println!("Purge {}, {:02X?}", frame_len, &self.read_buffer[..frame_len]);
                Err(e.into())
            }
        };
        self.read_buffer.copy_within(frame_len..self.read_offset, 0);
        self.read_offset -= frame_len;
        result
    }

    pub(crate) fn probe(&mut self) -> Result<(), Error> {
        self.write_packet(&wire_format::Packet::Probe(wire_format::PROBE_HOST))?;
        loop {
            let packet = self.read_packet()?;
            if let Some(packet) = packet {
                match packet {
                    wire_format::Packet::Probe(_value) => {
                        break;
                    }
                    _ => (),
                }
            }
        }
        Ok(())
    }

    pub(crate) fn set_channel(&mut self, channel: u8) -> Result<(), Error> {
        self.write_packet(&wire_format::Packet::Channel(channel))
    }

    pub(crate) fn start_capture(&mut self) -> Result<(), Error> {
        self.write_packet(&wire_format::Packet::CaptureStart)
    }

    pub(crate) fn stop_capture(&mut self) -> Result<(), Error> {
        self.write_packet(&wire_format::Packet::CaptureStop)
    }

    pub(crate) fn receive(&mut self) -> Result<Option<wire_format::Packet>, Error> {
        self.read_packet()
    }
}
