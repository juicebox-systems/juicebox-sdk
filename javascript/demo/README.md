## Demo

In order to run the demo, first run:
```sh
wasm-pack build ../../rust/bridge/wasm --out-dir ../../../javascript/juicebox-sdk --out-name juicebox-sdk --target nodejs
```

Then run `npm install`. Afterwards, the demo script can be run with `./demo.ts`

```sh
Usage: demo [options]

Options:
  -c, --configuration <value>    The configuration for the client SDK, in JSON format
  -a, --auth-tokens <value>      The auth token for the client SDK, as a JSON string mapping realm ID to base64-encoded JWT
  -t, --tls-certificate <value>  The path to the TLS certificate used by the realms in DER format
  -h, --help                     display help for command
```
