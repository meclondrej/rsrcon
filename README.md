# rsrcon
A simple RCON client written in rust

## Protocol Compatibility

Protocol|Compatibility
-|-
Source|Supported
Goldsrc|Supported
Minecraft|Planned

## OS Compatibility

This crate uses TCP functionality from `std`, so it should be compatible with most untested OSes.

Operating system|Compatibility
-|-
Linux|Supported (tested)
Windows|Untested
Mac OS|Untested

**NOTE**: Windows' `cmd.exe` may not support some terminal features (like ANSI codes) used by [`rpassword`](https://crates.io/crates/rpassword).
