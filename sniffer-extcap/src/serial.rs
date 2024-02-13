use crate::Error;
use ieee802154_sniffer_wire_format as wire_format;
use std::time::Duration;

pub(crate) struct DeviceSerial {
    port: Box<dyn serialport::SerialPort>,
    read_buffer: [u8; 4096],
    read_offset: usize,
}

impl DeviceSerial {
    pub(crate) fn open(name: &str) -> Result<Self, serialport::Error> {
        let mut port = serialport::new(name, 115_200)
            .timeout(Duration::from_millis(100))
            .open()?;
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

    fn read_packet(&mut self) -> Result<Option<wire_format::Packet>, Error> {
        let bytes = self.port.read(&mut self.read_buffer[self.read_offset..])?;
        self.read_offset += bytes;
        let part = &self.read_buffer[..self.read_offset];
        let mut frame_len = 0;
        for n in 0..part.len() {
            let b = self.read_buffer[n];
            if b == 0 {
                frame_len = n + 1;
                break;
            }
        }
        if frame_len > 0 {
            match wire_format::Packet::decode(&mut self.read_buffer[..frame_len]) {
                Ok((packet, remainder)) => {
                    let used = self.read_offset - remainder.len();
                    self.read_buffer.copy_within(used..self.read_offset, 0);
                    self.read_offset -= used;
                    Ok(Some(packet))
                }
                Err(e) => {
                    self.read_offset -= frame_len;
                    Err(e.into())
                }
            }
        } else {
            Ok(None)
        }
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
