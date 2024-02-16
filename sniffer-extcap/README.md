# Wireshark extcap application

[Extcap developer documentation](https://www.wireshark.org/docs/wsdg_html_chunked/ChCaptureExtcap.html).

## Build and install

Build using cargo,

```shell
cargo build --release
```

Install into Wireshark's extcap directory,

```shell
cp target/release/ieee802154-sniffer-extcap ${HOME}/.local/lib/wireshark/extcap/
```

Start a sniffer device and run Wireshark.
