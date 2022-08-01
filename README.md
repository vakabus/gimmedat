**WARNING:** this project is under development, is not properly tested and all possible failures have not been properly handled

---

# Gimmedat

You went on a trip with couple of friends. Each one of you had a fancy camera and took couple of gigabytes of pictures. How do you share all the photos toghether wihout paying for expensive cloud storage? That's where gimmedat comes in. This tool allows the owner to create upload links and anyone having them can then upload any files to the server.

## Design goals

- works on Linux
- simple to setup (no external services needed, just run one binary)
- no persistent storage on the server except for the data files
- one upload link, multiple files
- files can be uploaded by people with non-technical background

## Usage (for development)

```sh
cargo run -- --secret supersecretsecret
firefox http://localhost:3000/
```

## Alternatives

- [Magic Wormhole](https://github.com/magic-wormhole/magic-wormhole) - no need for a server, usually requires relay and the publicly hosted one is slow, requires synchronous cooperation between parties sharing files