mod error;
mod serial;

use error::Error;

use std::{
    io::{stdout, Write},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use byteorder::{ByteOrder, LittleEndian};
use clap::Parser;
use ieee802154_sniffer_wire_format as wire_format;
use lazy_static::lazy_static;
use pcap_file::{
    pcap::{PcapHeader, PcapPacket, PcapWriter},
    DataLink,
};
use r_extcap::{
    config::{ConfigOptionValue, SelectorConfig},
    controls::{synchronous::ExtcapControlSender, ControlCommand, ControlPacket},
    interface::{Dlt, Interface, Metadata},
    ExtcapStep,
};
use signal_hook;

const NXP_VID: u16 = 0x0d28;
const NXP_CMSIS_DAP_PID: u16 = 0x0204;

const SILICON_LABS_VID: u16 = 0x10c4;
const SILICON_LABS_UART_PID: u16 = 0xea60;
#[derive(Debug, Parser)]
pub struct AppArgs {
    #[command(flatten)]
    extcap: r_extcap::ExtcapArgs,
    #[arg(long, default_value = "11")]
    channel: String,
}
static DLT: Dlt = Dlt {
    data_link_type: DataLink::IEEE802_15_4_TAP,
    name: std::borrow::Cow::Borrowed("IEEE802154_TAP"),
    display: std::borrow::Cow::Borrowed("IEEE 802.15.4 TAP"),
};

lazy_static! {
    static ref METADATA: Metadata = Metadata {
        help_url: "https://github.com/blueluna/ieee802154-sniffer".into(),
        display_description: "IEEE 802.15.4 Sniffer".into(),
        ..r_extcap::cargo_metadata!()
    };
    static ref CAPTURE_INTERFACE_802154_TAP: Interface = Interface {
        value: "802.15.4".into(),
        display: "IEEE 802.15.4 Sniffer".into(),
        dlt: DLT.clone(),
    };
    static ref CONFIG_CHANNEL: SelectorConfig = SelectorConfig::builder()
        .config_number(3)
        .call("channel")
        .display("Channel")
        .tooltip("Channel Selector")
        .default_options([
            ConfigOptionValue::builder()
                .value("11")
                .display("11")
                .default(true)
                .build(),
            ConfigOptionValue::builder()
                .value("12")
                .display("12")
                .build(),
            ConfigOptionValue::builder()
                .value("13")
                .display("13")
                .build(),
            ConfigOptionValue::builder()
                .value("14")
                .display("14")
                .build(),
            ConfigOptionValue::builder()
                .value("15")
                .display("15")
                .build(),
            ConfigOptionValue::builder()
                .value("16")
                .display("16")
                .build(),
            ConfigOptionValue::builder()
                .value("17")
                .display("17")
                .build(),
            ConfigOptionValue::builder()
                .value("18")
                .display("18")
                .build(),
            ConfigOptionValue::builder()
                .value("19")
                .display("19")
                .build(),
            ConfigOptionValue::builder()
                .value("20")
                .display("20")
                .build(),
            ConfigOptionValue::builder()
                .value("21")
                .display("21")
                .build(),
            ConfigOptionValue::builder()
                .value("22")
                .display("22")
                .build(),
            ConfigOptionValue::builder()
                .value("23")
                .display("23")
                .build(),
            ConfigOptionValue::builder()
                .value("24")
                .display("24")
                .build(),
            ConfigOptionValue::builder()
                .value("25")
                .display("25")
                .build(),
            ConfigOptionValue::builder()
                .value("26")
                .display("26")
                .build(),
        ])
        .build();
}

fn main() -> Result<(), Error> {
    let args = AppArgs::parse();

    if !args.extcap.capture {
        if let Some(_filter) = args.extcap.extcap_capture_filter {
            std::process::exit(0);
        }
    }

    let extcap_args = match args.extcap.run() {
        Ok(args) => args,
        Err(_) => {
            eprintln!("Failed to parse arguments");
            std::process::exit(1);
        }
    };

    match extcap_args {
        ExtcapStep::Interfaces(interfaces_step) => {
            let mut interfaces = vec![];
            let mut channels = vec![];
            if let Ok(ports) = serialport::available_ports() {
                for port in ports {
                    match port.port_type {
                        serialport::SerialPortType::UsbPort(ref usb_port) => {
                            let probe = match (usb_port.vid, usb_port.pid) {
                                (NXP_VID, NXP_CMSIS_DAP_PID) => true,
                                (SILICON_LABS_VID, SILICON_LABS_UART_PID) => true,
                                (_vid, _pid) => false,
                            };
                            if probe {
                                if let Ok(mut channel) = serial::DeviceSerial::open(
                                    &port.port_name,
                                    std::time::Duration::from_millis(500),
                                ) {
                                    match channel.probe() {
                                        Ok(()) => {
                                            channels.push(port.port_name);
                                        }
                                        Err(e) => {
                                            eprintln!("Probe failed, {:?}", e);
                                        }
                                    }
                                }
                            }
                        }
                        _ => (),
                    }
                }
            }
            for channel in channels {
                interfaces.push(Interface {
                    value: std::borrow::Cow::Owned(channel),
                    display: "IEEE 802.15.4 Sniffer".into(),
                    dlt: DLT.clone(),
                })
            }
            interfaces_step.list_interfaces(&METADATA, &interfaces.iter().collect::<Vec<_>>(), &[]);
        }
        ExtcapStep::Dlts(dlts_step) => {
            dlts_step
                .print_from_interfaces(&[&*CAPTURE_INTERFACE_802154_TAP])
                .unwrap();
        }
        ExtcapStep::Config(config_step) => config_step.list_configs(&[&*CONFIG_CHANNEL]),
        ExtcapStep::ReloadConfig(_reload_config_step) => {
            panic!("Unsupported operation");
        }
        ExtcapStep::Capture(capture_step) => {
            let mut controls = (
                capture_step.spawn_channel_control_reader(),
                capture_step.new_control_sender(),
            );

            if let (Some(control_reader), Some(_control_sender)) = &mut controls {
                let packet = control_reader.read_packet().unwrap();
                assert_eq!(packet.command, ControlCommand::Initialized);
            }

            let pcap_header = PcapHeader {
                datalink: DataLink::IEEE802_15_4_TAP,
                endianness: pcap_file::Endianness::Big,
                ..Default::default()
            };
            let mut pcap_writer = PcapWriter::with_header(capture_step.fifo, pcap_header).unwrap();

            let channel = u8::from_str(&args.channel).unwrap();

            let serialport = if capture_step.interface.is_empty() {
                let ports = serialport::available_ports().unwrap();
                if ports.len() != 1 {
                    panic!("There are more or less than one serial ports. Don't know which one to use.");
                }
                ports[0].port_name.clone()
            } else {
                capture_step.interface.to_string()
            };

            let mut device =
                serial::DeviceSerial::open(&serialport, std::time::Duration::from_millis(1))
                    .expect("Failed to open port");

            device.set_channel(channel).unwrap();

            device.start_capture().unwrap();

            let term = Arc::new(AtomicBool::new(false));
            signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term))?;

            while !term.load(Ordering::Relaxed) {
                if let (Some(control_reader), Some(control_sender)) = &mut controls {
                    if let Some(control_packet) = control_reader.try_read_packet() {
                        handle_control_packet(&control_packet, control_sender).unwrap();
                    }
                }

                if let Ok(packet) = device.receive() {
                    if let Some(packet) = packet {
                        match packet {
                            wire_format::Packet::CaptureFrame(ref frame) => {
                                let mut tap_data_offset = 0;
                                let mut tap_data = [0u8; 512];
                                tap_data[0] = 0; // version
                                tap_data[1] = 0; // reserved
                                                 // header length 16-bit
                                tap_data_offset += 4;
                                LittleEndian::write_u16(
                                    &mut tap_data[tap_data_offset..tap_data_offset + 2],
                                    0,
                                ); // FCS type
                                LittleEndian::write_u16(
                                    &mut tap_data[tap_data_offset + 2..tap_data_offset + 4],
                                    1,
                                ); // length
                                LittleEndian::write_u32(
                                    &mut tap_data[tap_data_offset + 4..tap_data_offset + 8],
                                    0,
                                ); // None
                                tap_data_offset += 8;
                                LittleEndian::write_u16(
                                    &mut tap_data[tap_data_offset..tap_data_offset + 2],
                                    3,
                                ); // Channel plan
                                LittleEndian::write_u16(
                                    &mut tap_data[tap_data_offset + 2..tap_data_offset + 4],
                                    3,
                                ); // length
                                LittleEndian::write_u32(
                                    &mut tap_data[tap_data_offset + 4..tap_data_offset + 8],
                                    u32::from(channel),
                                ); // channel
                                tap_data_offset += 8;
                                if let Some(rssi) = frame.received_signal_strength_indicator {
                                    let rssi = (rssi as f32) / 1000.0f32;
                                    LittleEndian::write_u16(
                                        &mut tap_data[tap_data_offset..tap_data_offset + 2],
                                        1,
                                    ); // RSSI
                                    LittleEndian::write_u16(
                                        &mut tap_data[tap_data_offset + 2..tap_data_offset + 4],
                                        4,
                                    ); // length
                                    LittleEndian::write_f32(
                                        &mut tap_data[tap_data_offset + 4..tap_data_offset + 8],
                                        rssi,
                                    ); // RSSI
                                    tap_data_offset += 8;
                                }
                                if let Some(lqi) = frame.link_quality_index {
                                    LittleEndian::write_u16(
                                        &mut tap_data[tap_data_offset..tap_data_offset + 2],
                                        10,
                                    ); // LQI
                                    LittleEndian::write_u16(
                                        &mut tap_data[tap_data_offset + 2..tap_data_offset + 4],
                                        1,
                                    ); // length
                                    LittleEndian::write_u32(
                                        &mut tap_data[tap_data_offset + 4..tap_data_offset + 8],
                                        u32::from(lqi),
                                    ); // LQI
                                    tap_data_offset += 8;
                                }
                                LittleEndian::write_u16(
                                    &mut tap_data[2..4],
                                    tap_data_offset as u16,
                                ); // header length
                                let data = &frame.payload;
                                let length = data.len();
                                tap_data[tap_data_offset..tap_data_offset + length]
                                    .copy_from_slice(&data);

                                let pcap_packet = PcapPacket::new(
                                    SystemTime::now().duration_since(UNIX_EPOCH).unwrap(),
                                    (tap_data_offset + length) as u32,
                                    &tap_data[..tap_data_offset + length],
                                );
                                pcap_writer.write_packet(&pcap_packet).unwrap();
                            }
                            _ => (),
                        }
                        stdout().flush().unwrap();
                    }
                }
            }

            device.stop_capture().unwrap();
        }
    };
    Ok(())
}

fn handle_control_packet(
    _control_packet: &ControlPacket<'_>,
    _control_sender: &mut ExtcapControlSender,
) -> Result<(), ()> {
    // currently nothing to do here
    Ok(())
}
