use ieee802154_sniffer_wire_format as wire_format;
use std::convert::From;

#[derive(Debug)]
pub(crate) enum Error {
    IoError(std::io::Error),
    WireError(wire_format::Error),
    SerialPortError(serialport::Error),
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::IoError(error)
    }
}

impl From<wire_format::Error> for Error {
    fn from(error: wire_format::Error) -> Self {
        Error::WireError(error)
    }
}

impl From<serialport::Error> for Error {
    fn from(error: serialport::Error) -> Self {
        Error::SerialPortError(error)
    }
}
