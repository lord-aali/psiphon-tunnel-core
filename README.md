# Custom Psiphon Core

> If you find this project useful, please consider giving it a ⭐ on GitHub!

A custom build of the Psiphon Tunnel Core, pre-configured with a curated list of servers for optimized performance and connectivity.

[<img src="https://raw.githubusercontent.com/Faran-17/custom-psiphon-core/main/assets/Fa-Button.svg" alt="فارسی" width="120">](./README.fa.md)

## What is this?

This project provides a modified version of the open-source [Psiphon Tunnel Core](https://github.com/Psiphon-Inc/psiphon). The primary difference is that this build includes a specific, hand-picked list of entry points (servers) from various countries, which can result in a more stable and reliable connection for users in certain regions.

## Why use this custom build?

*   **Optimized Server List**: Instead of relying on the default server discovery, this version connects to a predefined set of high-quality servers.
*   **Simplicity**: No complex configuration is needed. Just run the executable and specify your desired country from the supported list.
*   **Transparency**: The full list of supported countries and servers is available directly in the source code, giving you full control.

## Supported Countries

This build is configured to work with servers in the following countries:

| Country          | Code | Country          | Code |
| ---------------- | ---- | ---------------- | ---- |
| Austria          | AT   | Italy            | IT   |
| Belgium          | BE   | Japan            | JP   |
| Bulgaria         | BG   | Latvia           | LV   |
| Brazil           | BR   | Netherlands      | NL   |
| Canada           | CA   | Norway           | NO   |
| Switzerland      | CH   | Poland           | PL   |
| Czech Republic   | CZ   | Romania          | RO   |
| Germany          | DE   | Serbia           | RS   |
| Denmark          | DK   | Sweden           | SE   |
| Estonia          | EE   | Singapore        | SG   |
| Spain            | ES   | Slovakia         | SK   |
| Finland          | FI   | Ukraine          | UA   |
| France           | FR   | United Kingdom   | GB   |
| Hungary          | HU   | United States    | US   |
| Ireland          | IE   | India            | IN   |

## Usage

To run the client, use the command line. You can specify the country you wish to connect through.

### Basic Example

This command will start the Psiphon proxy and listen for SOCKS connections on `127.0.0.1:10808`. It will connect through a server in the United States.

```bash
./psiphon -c US
```

### Command-Line Flags

```
Usage: psiphon [-b addr:port] [-c country] [-p proxy]

  -b string
        SOCKS bind address (default "127.0.0.1:10808")
  -c string
        Country code (e.g., US, DE, JP). See the list above for all valid values. (default "AT")
  -config string
        Psiphon config file. (if present, other flags are ignored)
  -d string
        Working directory (default "./")
  -p string
        Upstream proxy URL [format: socks5://127.0.0.1:1080].
```

## Building from Source

If you wish to build the project yourself, you will need to have Go installed.

```bash
# Clone the repository
git clone https://github.com/Faran-17/custom-psiphon-core.git
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
