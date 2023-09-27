# Use Ubuntu 22.04 as base image
FROM ubuntu:22.04

# Install required packages
RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    wget \
    libwrap0-dev \
    libpam0g-dev \
    libkrb5-dev \
    libldap2-dev \
    libssl-dev \
    curl \
    iproute2

# Download Dante
WORKDIR /tmp
RUN wget https://www.inet.no/dante/files/dante-1.4.3.tar.gz && \
    tar -xzf dante-1.4.3.tar.gz

# Compile and Install Dante
WORKDIR /tmp/dante-1.4.3
RUN ./configure --build=x86_64-linux-gnu && \
    make && \
    make install

# Cleanup
WORKDIR /
RUN rm -rf /tmp/*

ARG USER=socks

ENV WORKERS 4
ENV CONFIG /etc/sockd.conf

COPY etc/passwd /etc/passwd
COPY etc/passwd /etc/shadow
COPY etc/group /etc/group

COPY dante.conf ${CONFIG}
COPY generate.sh .

RUN adduser --system --no-create-home ${USER}

VOLUME /etc
# Expose SOCKS port
EXPOSE 1080

# Run Dante by default
CMD ["sockd"]
