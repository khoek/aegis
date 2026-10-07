# Native helpers

macOS builds embed `babeld` 1.14, built from its unmodified upstream source at
[`118774d`](https://github.com/jech/babeld/tree/118774d0c720cef016c0f3894ef8d24cd9cadd17).
Its source files retain their MIT, BSD, and public-domain notices.

WireGuard uses BoringTun (BSD-3-Clause); Ethernet interfaces use tun-rs
(Apache-2.0), both ordinary Cargo dependencies. No Homebrew installation is required.
