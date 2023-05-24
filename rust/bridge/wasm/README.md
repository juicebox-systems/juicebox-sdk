## Juicebox WASM Bindings

In order to generate the wasm bindings, you must run the `wasm-pack build` command from within this directory.

This will generate an npm package in the `pkg` directory that exposes all the necessary interfaces.

This package can be linked to from your `package.json` by adding a line similar to:
```
  "dependencies": {
    "juicebox-sdk": "file:../pkg"
  }
```

Alternatively, you can include the typescript/javascript directly through whatever means you prefer.

For reference, view the [demo typescript implementation](https://github.com/juicebox-systems/juicebox-sdk/tree/main/javascript/demo).

Eventually, this package should be published to the npm repository so consumers can simply depend on `juicebox-sdk` with a specified version and will not need to manually build it.
