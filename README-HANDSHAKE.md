# Handshake Demo with Rust and Go

Dear Eiger team,

This was a lot of work, but it was worth it. In fact it was super fun! I learned a lot about Rust and Go, and I'm glad I got to work on this project. I hope you enjoy reading this as much as I enjoyed writing it!
First time technologies: Go, IPFS, FFI, Noise Protocol, Mocking.

How was my time spent? 7 days for setting up the environment, 2 days I spent travelling. Effectively after 9 days I had two clients capable of reaching each other over a socks proxy. The devops stuff takes always more time than you want to spent on it.
2 days were spent for the handshake using the `snow` low level library. But since the requirement was to implement something on my own, I replaced it with my own code. It was however a good guidance. The replacement took me 1 day. The last two days were spent on writing some basic tests and mocking. The code should work on Linux and MacOS, I have tested it on both. I have not tested it on Windows, but since everything is setup in docker containers, there is a good chance it might work, or at least with minimal changes.

## Installation:

Pull the repo.

Install docker. Ideally add yourself to the docker group so you can run without sudo.

https://docs.docker.com/engine/install/

Install `just`.

https://github.com/casey/just

Run `just demo`.

### Where to find the code

The rust code is under `handshake/`. Additionally there is code under `plugin/plugins/client` and `plugin/plugins/server`. The code under `plugin/plugins` is the code that is preloaded into the kubo client. The code under `handshake` is the code that is called by the plugin.

### What it does and how it works

After the project is build you should be able to access the two kubo (go-ipfs) clients
via

`127.0.0.1:5001/webui` and `127.0.0.1:5002/webui`

No certificates are in place so you might have to accept `I'll take the risk` in your browser.

The two clients are connected to each other via a socks proxy. The two clients are running in their own docker container. The two containers are connected to the `bridge` network, which is connected to each of the two container networks.
The rather sophisticated setup was the simplest that came to my mind to avoid the clients talking to each other via their built in mechanism.

Without the proxy bridge there is no connection. The containers have internet access though. If you keep the default swarm key, then the two could talk just like any public ipfs nodes.
However, they have their own swarm key, and the bootstrap list is empty.
The original idea was to have the plugins talk to each other via the proxy (which works) and then have the plugins commuincate with the node. This is easier said than done.
First, because of quirks with the kubo client, out of tree plugins could not be used. I had to preload them, which is not a big deal, except I have to ship the whole client. Plus it prevents easily using FFI to talk back from Rust to Go.

It is still possible to talk back, but this is not implemented. The easiest way to achieve this is to make API calls against the RPC interface. This works not only for your side but also for the opposite side, for docker is listening internally on 0.0.0.0. So much for security :)

But making API calls is not implemented. There is another possibility I took into account but didn't implement it either. Once the connection is established, the two nodes can get the raw file descriptor of the connection. This can be handed over to the IPFS client (via return value of the function) and then registered with kubo.
Of course this puts a definite end to windows compatibility.

A nice side effect on working with kubo and trying to build on mac os, that I made a tiny little PR for allowing custom target to be built. It was accepted and is merged.
The larger PR I intend to work on is to get the plugin situation fixed. Kubo is the reference implementation and not being able to easily build out of tree plugins is a big deal.

## Functionality
The code is straight forward. Each side loads its plugin while the plugin of the opposite side is disabled. The plugin loads via its start function the rust function (FFI).
The Rust side does a little FFI stuff and then calls a pure rust function. This Rust function spawns a tokio runtime which then starts the handshake. Once the connection is encrypted, the two exchange their ipfs peer ids every second.

The easiest way to see what is going on is to look at the docker logs.

`docker logs -f ipfs_client` and `docker logs -f ipfs_server`

You can also see `docker logs -f dante-bridge` to see the proxy logs.

Note that the two clients continue to work while the connection is running. So they network does not block anything.

1. **Encrypted Handshake**: The protocol implemented was based on the noise protocol, a framework for building cryptographic protocols. For simplicity, NN with a pre shared key was used which is a simple 2-way handshake. Eliptic curve 25519 was used for key generation, for the  cipher ChaCha20Poly1305 was used for encryption and decryption, and the hash function BLAKE2s was used for hashing. All in all called Noise_NNpsk2_25519_ChaChaPoly_BLAKE2s.

2. **Mock Stream for Testing**: Both the Rust and Go implementations are equipped with mock streams to simulate TCP communication without actual network usage. I used the project a little bit as a playground to test out new stuff. The mocking is not yet ideal.

3. **FFI (Foreign Function Interface) Integration**: The Rust code is called by Go via FFI. This involves my first unsafe code, but it is not a big deal. Dealing with the libraries and making sure you always have the right dependencies is a bigger challenge.

## Development History

A lot of this is first time. Never did Go before, never FFI never mocking and of course never implemented a handshake myself before. But it worked out well and was a lot of fun.

### Major Roadblocks

1. **Plugin Loading**: Out of tree plugins are a nightmare with kubo. I tried all kind of trimpaths to no avail. At one point I pulled the plug and went for preloading the plugin.
That bite me back later on when I wanted to use FFI to talk back to Go. There seems to be no possibility to build both plugin and c-shared. Never mind, preloading works though it makes the project insanely large.

2. **Go's Version Hell**: Dealing with Go's dependency management was another nightmare. Reminded me of Python. Rust did a marvellous job in avoiding your code breaking because of dependency version changes. Well, admittably it was likely a skill issue, but I'd like to spend my efforts on better stuff than version dependencies.

3. **Trait Implementation Mismatches**: The usual ones. They are sometimes very time consuming to work out. Yet, once the code compiles it usually just works.

4. **Encryption and Decryption**: Ensuring that encryption and decryption operations worked as expected. If you want to have a look at the encrypted code hook yourself in with wireshark. If you think this is too much work, then you are right. Try

`docker exec -it dante-bridge tcpdump -i eth1 -A -n -c 100`

which should show you the tcp traffic. If I did everything correctly you should not be able to read anything.

5. **Test Configuration with Rust**: Using `#[cfg(test)]` in Rust can sometimes lead to unexpected compilation behaviors, especially when test-specific methods were intended to be exposed. A thorough understanding of Rust's conditional compilation was necessary.

## Conclusion

I am actually surprised to have gotton that far. Kubo was probably not the best decision. Iroh would have made it much easier, but hey who wants easy. I learned a lot about Rust, Go and IPFS.

Cheers Johannes
