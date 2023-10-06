# iwlar
A command line utility that triggers LAR using the 802.11 netlink API.

LAR (Location Aware Regulatory) is a mechanism by which Intel drivers automatically set the wireless interface's regulatory domain based on the wireless client's physical location. There's very little documentation about how LAR works. However, it's well known that it relies on country information advertised by nearby access points. Therefore, the wireless client must perform at least one scan to discover nearby APs and trigger the LAR process.

This utility's only goal is to initiate a passive scan using the minimum steps necessary to trigger the LAR process on the given wireless interface.

## Installation

```shell
# Install pre-requisites
sudo apt update
sudo apt install git libnl-genl-3-dev

# Download, build, and install iwlar
git clone https://github.com/intuitibits/iwlar.git
cd iwlar
make
sudo make iwlar
```

## Usage

```shell
Usage: iwlar [-h] [--version] <interface>
Options:
  -h, --help          Display this help message
  --version           Show version
```

Where `<interface>` is the name of the WLAN interface (e.g. `wlan0`) we need to trigger LAR on.

The command must be run as root since only privileged processes can initiate a scan.
