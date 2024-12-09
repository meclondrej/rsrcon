# rsrcon
A simple RCON client written in rust

## Protocol Compatibility

Protocol|Compatibility
-|-
Source|Supported
Goldsrc|Supported
Minecraft|Supported

## Usage

```
A simple RCON client written in rust

Usage: rsrcon [OPTIONS] <dest>

Arguments:
  <dest>  address of the server to connect to

Options:
  -P, --protocol <protocol>  protocol to use (default: source)
  -p, --password <password>  password set on the server
  -t, --timeout <timeout>    timeout of the connection stream in ms (default: 1000 ms)
  -h, --help                 Print help
```

## OS Compatibility

This crate uses TCP functionality from `std`, so it should be compatible with most untested OSes.

Operating system|Compatibility
-|-
Linux|Supported (tested)
Windows|Untested
Mac OS|Untested

**NOTE**: Windows' `cmd.exe` may not support some terminal features (like ANSI codes) used by [`rpassword`](https://crates.io/crates/rpassword).
