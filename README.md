# Gimmedat

You went on a trip with a couple of friends. Each one of you had a fancy camera and took a couple of gigabytes of pictures. How do you share all the photos without paying for expensive cloud storage? That's where `gimmedat` comes in. This tool allows the owner to create upload links and anyone having them can then upload any files to the server.

## Design goals

- works on Linux
- simple to setup (no external services needed, just run one binary)
- no persistent storage on the server except for the data files
- one upload link, multiple files
- files can be uploaded by people with a non-technical background

## Security

When uploading files, these invariants hold:

- a successfully uploaded file cannot be overwritten, failed partial files can be overwritten
- the upload directory will always contain fewer bytes that the data limit
- no data can be written to disk after the time limit expires

There are currently no known security issues invalidating the above invariants.

## Usage

```sh
# minimalistic example
gimmedat --secret secret

# all options example
gimmedat --secret supersecretsecret --listen-ip 127.0.0.1 --port 3000 --base-url "https://gimmedat.example.org"
firefox http://localhost:3000/
```

## Alternatives

- [Magic Wormhole](https://github.com/magic-wormhole/magic-wormhole) - no need for a server, usually requires relay and the publicly hosted one is slow, requires synchronous cooperation between parties sharing files