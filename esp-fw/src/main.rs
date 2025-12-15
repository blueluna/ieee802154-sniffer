#![no_std]
#![no_main]

use defmt;
use panic_rtt_target as _;
use embassy_executor::Spawner;
use embassy_futures::select::{select, Either};
use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, channel::Channel, signal::Signal};
use esp_hal::{Async, clock::CpuClock, timer::timg::TimerGroup, uart};
use esp_radio::ieee802154::Ieee802154;
use ieee802154_sniffer_wire_format as wire_format;

// This creates a default app-descriptor required by the esp-idf bootloader.
// For more information see: <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/app_image_format.html#application-description>
esp_bootloader_esp_idf::esp_app_desc!();

static CONTROL_CHANNEL: Channel<CriticalSectionRawMutex, wire_format::Packet, 1> = Channel::new();
static NEW_FRAME: Signal<CriticalSectionRawMutex, ()> = Signal::new();

#[embassy_executor::task]
async fn uart_reader(mut rx: uart::UartRx<'static, Async>) {

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
async fn radio_receive(mut radio: esp_radio::ieee802154::Ieee802154<'static>, mut tx: uart::UartTx<'static, Async>) {
    let mut configuration = esp_radio::ieee802154::Config {
        channel: 11,
        promiscuous: true,
        rx_when_idle: true,
        auto_ack_rx: false,
        auto_ack_tx: false,
        ..esp_radio::ieee802154::Config::default()
    };
    let mut capture_enable = false;
    let mut utx_buffer = [0; 512];
    loop {
        match select(NEW_FRAME.wait(), CONTROL_CHANNEL.receive()).await {
            Either::First(_) => {
                if let Some(received) = radio.raw_received() {
                    let size = usize::from(received.data[0]);
                    let rssi = received.data[size] as i8;
                    let part = &received.data[1..(size - 1)];
                    let lqi = esp_radio::ieee802154::rssi_to_lqi(rssi);

                    if capture_enable {
                        let payload = match wire_format::Payload::from_slice(part) {
                            Ok(payload) => payload,
                            Err(_) => {
                                defmt::error!("ZRX: Failed to decode payload");
                                continue;
                            }
                        };
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
                    wire_format::Packet::Probe(magic) => {
                        if magic == wire_format::PROBE_HOST {
                            let tx_packet = wire_format::Packet::Probe(wire_format::PROBE_DEVICE);
                            let uart_data = defmt::unwrap!(tx_packet.encode(&mut utx_buffer));
                            defmt::unwrap!(embedded_io_async::Write::write_all(&mut tx, uart_data).await);
                        }
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


#[esp_rtos::main]
async fn main(spawner: Spawner) {
    rtt_target::rtt_init_defmt!();

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(#[esp_hal::ram(reclaimed)] size: 65536);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let sw_interrupt =
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT);

    let mut ieee802154 = Ieee802154::new(peripherals.IEEE802154);
    ieee802154.set_rx_available_callback_fn(receive_available);

    let uart_config = uart::Config::default().with_baudrate(250_000).with_rx(uart::RxConfig::default().with_fifo_full_threshold(64));
    let (tx_pin, rx_pin) = (peripherals.GPIO16, peripherals.GPIO17);

    let uart0 = uart::Uart::new(peripherals.UART0, uart_config).unwrap().with_tx(tx_pin).with_rx(rx_pin).into_async();
    let (rx, tx) = uart0.split();

    esp_rtos::start(timg0.timer0, sw_interrupt.software_interrupt0);

    spawner.spawn(uart_reader(rx)).ok();
    spawner.spawn(radio_receive(ieee802154, tx)).ok();
}
