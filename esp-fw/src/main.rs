#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use defmt;
use defmt_rtt as _;
use embassy_executor::Spawner;
use embassy_futures::select::{select, Either};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, channel::Channel, signal::Signal};
use esp_backtrace as _;
use esp_ieee802154;
use hal::{clock::ClockControl, embassy, peripherals::{self, Peripherals}, prelude::*, timer::TimerGroup, uart, Uart, gpio};
use ieee802154_sniffer_wire_format as wire_format;

static CONTROL_CHANNEL: Channel<CriticalSectionRawMutex, wire_format::Packet, 1> = Channel::new();
static NEW_FRAME: Signal<CriticalSectionRawMutex, ()> = Signal::new();

#[embassy_executor::task]
async fn uart_reader(mut rx: uart::UartRx<'static, peripherals::UART0>) {

    let mut buf = [0; 512];
    let mut offset = 0;
    loop {
        match embedded_io_async::Read::read(&mut rx, &mut buf[offset..]).await {
            Ok(size) => {
                offset += size;
            }
            Err(_error) => {
                defmt::error!("URX: Failed to read UART, {}", _error);
            }
        }
        'inner: loop {
            let end_marker = buf.iter().position(|&b| b == 0x00);
            if let Some(pos) = end_marker {
                match wire_format::Packet::decode(&mut buf[..pos]) {
                    Ok((packet, _)) => {
                        CONTROL_CHANNEL.send(packet).await;
                    }
                    Err(_) => {
                        defmt::error!("URX: Failed to decode packet");
                        break 'inner;
                    }
                }
                let from = pos + 1;
                if offset > from {
                    buf.copy_within(from..offset, 0);
                    offset -= from;
                }
                else {
                    offset = 0;
                    break 'inner;
                }
            }
            else {
                break 'inner;
            }
        }
    }
}

fn receive_available()
{
    NEW_FRAME.signal(());
}

#[embassy_executor::task]
async fn radio_receive(mut radio: esp_ieee802154::Ieee802154<'static>, mut tx: uart::UartTx<'static, peripherals::UART0>) {
    let mut configuration = esp_ieee802154::Config {
        channel: 11,
        promiscuous: true,
        rx_when_idle: true,
        auto_ack_rx: false,
        auto_ack_tx: false,
        ..esp_ieee802154::Config::default()
    };
    let mut capture_enable = false;
    let mut utx_buffer = [0; 512];
    loop {
        match select(NEW_FRAME.wait(), CONTROL_CHANNEL.receive()).await {
            Either::First(_) => {
                if let Some(received) = radio.get_raw_received() {
                    let size = usize::from(received.data[0]);
                    let rssi = received.data[size] as i8;
                    let part = &received.data[1..(size - 1)];
                    let lqi = esp_ieee802154::rssi_to_lqi(rssi);

                    if capture_enable {
                        let payload = defmt::unwrap!(wire_format::Payload::from_slice(part));
                        let frame = wire_format::Frame { payload, channel: received.channel, received_signal_strength_indicator: Some(i32::from(rssi) * 1_000), link_quality_index: Some(lqi) };
                        let tx_packet = wire_format::Packet::CaptureFrame(frame);
                        let uart_data = defmt::unwrap!(tx_packet.encode(&mut utx_buffer));
                        defmt::unwrap!(embedded_io_async::Write::write_all(&mut tx, uart_data).await);
                    }
                }
            }
            Either::Second(packet) => {
                match packet {
                    wire_format::Packet::Channel(channel) => {
                        configuration.channel = channel;
                        defmt::info!("CTL: Set channel {}", configuration.channel);
                        radio.set_config(configuration);
                        // Hacky way to get the radio to actually change channel
                        let _ = radio.transmit_raw(&[0x02, 0x00, 0x04]);
                    }
                    wire_format::Packet::Power(_) => (),
                    wire_format::Packet::Probe(_magic) => {
                    },
                    wire_format::Packet::CaptureStart => {
                        defmt::info!("CTL: Start capture {}", configuration.channel);
                        radio.start_receive();
                        capture_enable = true;
                    }
                    wire_format::Packet::CaptureStop => {
                        capture_enable = false;
                        defmt::info!("CTL: Stop capture");
                    }
                    wire_format::Packet::NoOperation | wire_format::Packet::Reset | wire_format::Packet::CaptureFrame(_) => (),
                }
            }
        }
    }
}

#[main]
async fn main(spawner: Spawner) {
    let peripherals = Peripherals::take();
    let mut system = peripherals.SYSTEM.split();

    let clocks = ClockControl::max(system.clock_control).freeze();
    let timer_group0 = TimerGroup::new(peripherals.TIMG0, &clocks);

    let mut ieee802154 = esp_ieee802154::Ieee802154::new(peripherals.IEEE802154, &mut system.radio_clock_control);

    ieee802154.set_rx_available_callback_fn(receive_available);

    embassy::init(&clocks, timer_group0);

    let uart_config = uart::config::Config { baudrate: 250_000, ..uart::config::Config::default() };
    type Pins<'a> = uart::TxRxPins<'a, gpio::GpioPin<gpio::Output<gpio::PushPull>, 2>, gpio::GpioPin<gpio::Input<gpio::Floating>, 0>>;
    let mut uart0 = Uart::new_with_config(peripherals.UART0, uart_config, None::<Pins<'_>>, &clocks);
    uart0
        .set_rx_fifo_full_threshold(64)
        .unwrap();
    uart0.set_rx_timeout(Some(3)).unwrap();
    let (tx, rx) = uart0.split();

    defmt::unwrap!(spawner.spawn(uart_reader(rx)));
    defmt::unwrap!(spawner.spawn(radio_receive(ieee802154, tx)));
}
