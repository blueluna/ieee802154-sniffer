#![cfg_attr(not(feature = "std"), no_std)]

/// 802.15.4 sniffer wire format
use core::convert::From;
use serde::{Deserialize, Serialize};

pub const PROBE_HOST: u32 = 0xfedcba98;
pub const PROBE_DEVICE: u32 = 0x01234567;

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum Error {
    PostcardError(postcard::Error),
}

impl From<postcard::Error> for Error {
    fn from(value: postcard::Error) -> Self {
        Self::PostcardError(value)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Error {
    fn format(&self, fmt: defmt::Formatter) {
        match *self {
            Error::PostcardError(ref error) => {
                defmt::write!(fmt, "Error {}", error);
            }
        }
    }
}

pub type Payload = heapless::Vec<u8, 256>;

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Frame {
    pub link_quality_index: Option<u8>,
    pub payload: Payload,
}

#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum Packet {
    NoOperation,
    Reset,
    Probe(u32),
    Channel(u8),
    Power(i32),
    CaptureStart,
    CaptureStop,
    CaptureFrame(Frame),
}

impl Packet {
    pub fn encode<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        postcard::to_slice_cobs(self, buffer).map_err(|e| e.into())
    }

    pub fn decode(buffer: &mut [u8]) -> Result<(Self, &mut [u8]), Error> {
        postcard::take_from_bytes_cobs(buffer).map_err(|e| e.into())
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for Packet {
    fn format(&self, fmt: defmt::Formatter) {
        match *self {
            Self::NoOperation => {
                defmt::write!(fmt, "NO-OP");
            }
            Self::Reset => {
                defmt::write!(fmt, "Reset");
            }
            Self::Probe(magic) => {
                defmt::write!(fmt, "Probe {:08x}", magic);
            }
            Self::Channel(channel) => {
                defmt::write!(fmt, "Channel {}", channel);
            }
            Self::Power(power) => {
                defmt::write!(fmt, "Power {}", power);
            }
            Self::CaptureStart => {
                defmt::write!(fmt, "Capture Start");
            }
            Self::CaptureStop => {
                defmt::write!(fmt, "Capture Stop");
            }
            Self::CaptureFrame(ref frame) => {
                defmt::write!(fmt, "Capture Frame {}", frame.payload.len());
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn encode() {
        let buffer = &mut [0u8; 32];
        {
            let output = (&Packet::Reset).encode(buffer).unwrap();
            assert_eq!(&[0x02, 0x01, 0x00], output);
        }
        {
            let output = (&Packet::Power(0)).encode(buffer).unwrap();
            assert_eq!(&[0x02, 0x04, 0x01, 0x00], output);
        }
        {
            let payload = Payload::from_slice(&[0x02, 0x00, 0x04]).unwrap();
            let output = (&Packet::CaptureFrame(Frame {
                payload,
                link_quality_index: None,
            }))
                .encode(buffer)
                .unwrap();
            assert_eq!(&[0x02, 0x07, 0x03, 0x03, 0x02, 0x02, 0x04, 0x00], output);
        }
    }

    #[test]
    fn decode() {
        let mut nothing: [u8; 0] = [];
        {
            let mut data = [0x02, 0x01, 0x00];
            let (packet, remainder) = Packet::decode(&mut data).unwrap();
            assert_eq!(Packet::Reset, packet);
            assert_eq!(&mut nothing, remainder);
        }
        {
            let mut data = [0x02, 0x04, 0x01, 0x00];
            let (packet, remainder) = Packet::decode(&mut data).unwrap();
            assert_eq!(Packet::Power(0), packet);
            assert_eq!(&mut nothing, remainder);
        }
        {
            let mut data = [0x02, 0x06, 0x00];
            let (packet, remainder) = Packet::decode(&mut data).unwrap();
            assert_eq!(Packet::CaptureStop, packet);
            assert_eq!(&mut nothing, remainder);
        }
        {
            let mut data = [0x02, 0x07, 0x03, 0x03, 0x02, 0x02, 0x04, 0x00];
            let (packet, remainder) = Packet::decode(&mut data).unwrap();
            let payload = Payload::from_slice(&[0x02, 0x00, 0x04]).unwrap();
            let frame = Frame {
                payload,
                link_quality_index: None,
            };
            assert_eq!(Packet::CaptureFrame(frame), packet);
            assert_eq!(&mut nothing, remainder);
        }
    }
}
