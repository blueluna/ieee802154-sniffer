#![no_std]
#![no_main]

use defmt;
use embassy_executor::Spawner;
use embassy_futures::select::{select, Either};
use embassy_nrf::{
    bind_interrupts, peripherals, radio, uarte,
};
use embassy_sync::{blocking_mutex::raw::ThreadModeRawMutex, channel::Channel};

use {defmt_rtt as _, panic_probe as _};
use ieee802154_sniffer_wire_format as wire_format;

bind_interrupts!(struct Irqs {
    RADIO => radio::InterruptHandler<peripherals::RADIO>;
    UARTE0_UART0 => uarte::InterruptHandler<peripherals::UARTE0>;
});

static CHANNEL: Channel<ThreadModeRawMutex, wire_format::Packet, 4> = Channel::new();

#[embassy_executor::task]
async fn uart_reader(mut rx: uarte::UarteRx<'static, peripherals::UARTE0>) {

    let mut buf = [0; 512];
    let mut offset = 0;
    loop {
        match rx.read(&mut buf[offset..offset+1]).await {
            Ok(()) => {
                offset += 1;
            }
            Err(_error) => {
                defmt::error!("URX: Failed to read UART, {}", _error);
            }
        }
        if buf[offset - 1] == 0 {
            match wire_format::Packet::decode(&mut buf[..offset]) {
                Ok((packet, remainder)) => {
                    defmt::info!("URX: Received {}, {}", remainder.len(), packet);
                    CHANNEL.send(packet).await;
                }
                Err(_) => {
                    defmt::error!("URX: Failed to decode packet");
                }
            }
            offset = 0;
        }
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = embassy_nrf::config::Config::default();
    config.hfclk_source = embassy_nrf::config::HfclkSource::ExternalXtal;

    let p = embassy_nrf::init(config);

    let mut radio = radio::ieee802154::Radio::new(p.RADIO, Irqs);

    let mut uart_config = uarte::Config::default();
    uart_config.parity = uarte::Parity::EXCLUDED;
    uart_config.baudrate = uarte::Baudrate::BAUD115200;

    let uart = uarte::Uarte::new(p.UARTE0, Irqs, p.P1_08, p.P0_06, uart_config);
    let (mut tx, rx) = uart.split();

    defmt::unwrap!(spawner.spawn(uart_reader(rx)));

    let mut capture_enable = false;
    let mut utx_buffer = [0u8; 512];

    loop {
        let mut rx_packet = radio::ieee802154::Packet::new();
        {
            match select(radio.receive(&mut rx_packet), CHANNEL.receive()).await {
                Either::First(result) => {
                    match result {
                        Ok(()) => {
                            if capture_enable {
                                let payload = defmt::unwrap!(wire_format::Payload::from_slice(&rx_packet));
                                let frame = wire_format::Frame { payload, link_quality_index: Some(rx_packet.lqi()) };
                                let tx_packet = wire_format::Packet::CaptureFrame(frame);
                                let uart_data = defmt::unwrap!(tx_packet.encode(&mut utx_buffer));
                                defmt::unwrap!(tx.write(uart_data).await);
                            }
                        }
                        Err(crc) => {
                            defmt::error!("Invalid CRC {=u16:04x}", crc);
                        }
                    }
                }
                Either::Second(ref packet) => {
                    defmt::info!("RRX: Received {}", packet);
                    match packet {
                        wire_format::Packet::Channel(channel) => { radio.set_channel(*channel); }
                        wire_format::Packet::Power(_power) => (),
                        wire_format::Packet::Probe(magic) => {
                            if *magic == wire_format::PROBE_HOST {
                                let tx_packet = wire_format::Packet::Probe(wire_format::PROBE_DEVICE);
                                let uart_data = defmt::unwrap!(tx_packet.encode(&mut utx_buffer));
                                defmt::unwrap!(tx.write(uart_data).await);
                            }
                        },
                        wire_format::Packet::CaptureStart => { capture_enable = true; }
                        wire_format::Packet::CaptureStop => { capture_enable = false; }
                        wire_format::Packet::NoOperation | wire_format::Packet::Reset | wire_format::Packet::CaptureFrame(_) => (),
                    }
                }
            }
        }
    }
}
