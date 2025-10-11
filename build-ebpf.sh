#!/bin/sh

set -e

ME=$0
echo "$ME" | grep '\/' >/dev/null 2>&1 || {
    ME=$(realpath "$(which "$ME")")
}

cd "$(dirname "$ME")"

cargo +nightly build --package etherip-xdp-ebpf -Z build-std=core --bins --profile release-ebpf --target=bpfel-unknown-none

cp ./target/bpfel-unknown-none/release-ebpf/etherip-xdp ./etherip-xdp/assets/
