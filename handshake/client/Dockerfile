# Start from the Rust official image
FROM --platform=${BUILDPLATFORM:-linux/amd64} rust:latest AS builder

ARG TARGETOS TARGETARCH

# Set the working directory inside the container
WORKDIR /rustlib

# Copy the Rust project into the container
COPY . .
COPY ../common /rustlib/common


# Install necessary tools and libraries
RUN apt-get update && apt-get upgrade -y

# Use RUN instructions to execute a shell script with if-else logic
RUN if [ "$TARGETARCH" = "amd64" ]; then \
    apt-get update && apt-get install -y g++-x86-64-linux-gnu g++-x86-64-linux-gnu; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
    apt-get update && apt-get install -y g++-aarch64-linux-gnu g++-aarch64-linux-gnu; \
    fi

RUN if [ "$TARGETARCH" = "amd64" ]; then \
    rustup target add x86_64-unknown-linux-gnu && rustup toolchain install stable-x86_64-unknown-linux-gnu; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
    rustup target add aarch64-unknown-linux-gnu && rustup toolchain install stable-aarch64-unknown-linux-gnu; \
    fi
RUN apt-get install gcc g++ git libncurses5-dev

RUN if [ "$TARGETARCH" = "amd64" ]; then \
        export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc; \
        export CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc; \
        export CXX_x86_64_unknown_linux_gnu=x86_64-linux-gnu-g++; \
        cargo build --release --target=x86_64-unknown-linux-gnu; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
        CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
        CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc \
        CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++ \
        cargo build --release --target=aarch64-unknown-linux-gnu; \
    fi
