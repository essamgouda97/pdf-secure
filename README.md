## pdf-secure

Fun project in Rust that allows the user to setup a USB stick with secure PDF files to be viewed X number of times. The releases contain a windows executable and the project was tested only on windows (adding support for other platforms should be easy, will work on it :D).

## Build for release command
Before building you need to do the following:
1. Run `./generate_keys.sh` to generate the keys for the encryption.
2. `cargo build --target x86_64-pc-windows-gnu --release` for windows release.

## Usage
Check the release notes for the latest release.
