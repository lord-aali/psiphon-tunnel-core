# Custom Psiphon Core

> If you find this project useful, please consider giving it a ⭐ on GitHub!

A custom build of the Psiphon Tunnel Core, pre-configured with a curated list of servers for optimized performance and connectivity.

[نسخه فارسی](./README.fa.md)

## What is this?

This project provides a modified version of the open-source [Psiphon Tunnel Core](https://github.com/Psiphon-Inc/psiphon). The primary difference is that this build includes a specific, hand-picked list of entry points (servers) from various countries, which can result in a more stable and reliable connection for users in certain regions.

## Why use this custom build?

*   **Optimized Server List**: Instead of relying on the default server discovery, this version connects to a predefined set of high-quality servers.
*   **Simplicity**: No complex configuration is needed. Just run the executable and specify your desired country from the supported list.
*   **Transparency**: The full list of supported countries and servers is available directly in the source code, giving you full control.

## Supported Countries

Run the executable for the first time to create data directory if you haven't already then use the following command to see the list of available countries:

```bash
./psiphon -list
```


## Usage

To run the client, use the command line. You can specify the country you wish to connect through.

### Basic Example

This command will start the Psiphon proxy and listen for SOCKS connections on `127.0.0.1:10808`. It will connect through a server in the United States.

```bash
./psiphon -c US
```

### Command-Line Flags

```
Usage: psiphon [-b addr:port] [-c country] [-p proxy] [-wo|-mo|-mp] [-list]

  -b string
        SOCKS bind address (default "127.0.0.1:10808")
  -c string
        Country code (e.g., US, DE, JP). Use -list to see available values. (default "AT")
  -config string
        Psiphon config file. (if present, other flags are ignored)
  -d string
        Working directory (default "./")
  -list
        List available egress countries from the local data store
  -p string
        Upstream SOCKS5 proxy URL [format: socks5://127.0.0.1:1080]
  -wo
        Enable Cloudflare WARP (WireGuard) only
  -mo
        Enable Cloudflare MASQUE (HTTP/2) only
  -mp
        Enable Cloudflare MASQUE (HTTP/2) over Psiphon
```

Examples:

```bash
./psiphon -list
./psiphon -c US
./psiphon -wo
./psiphon -mo
./psiphon -mp -c US
```

Identity files:
- WireGuard WARP: `data/warp/`
- MASQUE: `data/masque/`

## Building from Source

If you wish to build the project yourself, you will need to have Go installed.

```bash
# Clone the repository
git clone https://github.com/lord-aali/psiphon-tunnel-core.git
cd custom-psiphon-core

# Build the project
go build -buildvcs=false
```

## Contributing

Contributions are welcome! If you have suggestions for new servers or improvements to the code, feel free to open an issue or submit a pull request.

## Donations

If you'd like to support the project, you can donate using the following cryptocurrency addresses:

*   **BTC**: `bc1quuj84xva5tn2rued5l2rk7hsk00w8cdyzp2qxt`
*   **TRX/USDT**: `TDtSRmzUy2dqDN3Toy2383c7YbjVmNDaX8`
*   **BNB**: `0x15fc1eb651e183924b7e8f3097c53f942a9f0d10`
*   **ETH**: `0x15fc1eb651e183924b7e8f3097c53f942a9f0d10`
