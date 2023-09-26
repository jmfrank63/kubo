# Start from the Rust official image
FROM rust:latest AS builder

# Set the working directory inside the container
WORKDIR /rustlib

# Copy the Rust project into the container
COPY . .

# Install necessary tools and libraries
RUN apt-get update --allow-insecure-repositories && apt-get upgrade -y
RUN apt-get install gcc g++ git gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libncurses5-dev
RUN rustup target add aarch64-unknown-linux-gnu
RUN rustup toolchain install stable-aarch64-unknown-linux-gnu
RUN CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
    CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
    cargo build --release --target=aarch64-unknown-linux-gnu
