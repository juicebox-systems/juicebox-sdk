## Loam WASM Bindings

In order to generate the wasm bindings, you must run the `wasm-pack build` command from within this directory.

This will generate an npm package in the `pkg` directory that exposes all the necessary interfaces.

This package can be linked to from your `package.json` by adding a line similar to:
```
  "dependencies": {
    "loam-sdk": "file:../pkg"
  }
```

You can then use it like so:
```javascript
import { Client, Configuration, Realm, RegisterError } from "loam-sdk";

const realm = new Realm('https://127.0.0.1/', new Uint8Array(32).fill(0), new Uint8Array(16).fill(0));
const configuration = new Configuration([realm], 1, 1);
const client = new Client(configuration, "some-token");

const encoder = new TextEncoder();

client.register(encoder.encode("1234"), encoder.encode("apollo"), 2)
    .then(() => console.log("Registered!"))
    .catch((error) => console.log(error === RegisterError.Protocol));
```

Alternatively, you can include the typescript/javascript directly through whatever means you prefer.

Eventually, this package should be published to the npm repository so consumers can simply depend on `loam-sdk` with a specified version and will not need to manually build it.
