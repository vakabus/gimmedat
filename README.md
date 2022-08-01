**WARNING:** this project is under development, is not properly tested and all possible failures have not been properly handled
---

# Gimmedat

You went on a trip with couple of friends. Each one of you had a fancy camera and took couple of gigabytes of pictures. How do you share all the photos toghether wihout paying for expensive cloud storage? That's where gimmedat comes in. This tool allows the owner to create upload links and anyone having them can then upload any files to the server.

## Usage (for development)

```sh
cargo run -- --secret supersecretsecret
firefox http://localhost:3000/
```

## Alternatives

- [Magic Wormhole](https://github.com/magic-wormhole/magic-wormhole) - no need for a server, usually requires relay and the publicly hosted one is slow, requires synchronous cooperation between parties sharing files