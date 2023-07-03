# Tokens

A CLI tool for validation and creation of auth tokens. While you likely will want to integrate token creation into your server, this tool allows for quickly generating canonical tokens to validate your implementation against or to use for testing purposes. Additionally, it supports validating tokens created by other means to verify they match the expected format.

This tool can be built with:
```
cargo build -p juicebox-sdk-tokens
```

```
Usage: tokens <COMMAND>

Commands:
  create    Create an auth token for a tenant
  validate  Validate an auth token for a tenant
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

# Create

Create an auth token for a given tenant.

```
Usage: tokens create <USER> <TENANT> <REALM> <KEY> <VERSION>

Arguments:
  <USER>     An alphanumeric user ID that this token should be valid for
  <TENANT>   An alphanumeric tenant ID
  <REALM>    The ID of the realm, as a hex string, that the token should be valid for
  <KEY>      The key, as a hex string, that the token should be signed with
  <VERSION>  The integer version of the signing key

Options:
  -h, --help  Print help
```

# Validate

Validate an auth token for a tenant. Specific errors and warnings will be printed to help you diagnose any issues with your token creation code.

```
Usage: tokens validate <TOKEN> <USER> <TENANT> <REALM> <KEY> <VERSION>

Arguments:
  <TOKEN>    The token to validate
  <USER>     The alphanumeric user ID that this token was created with
  <TENANT>   The alphanumeric tenant ID that this token was created with
  <REALM>    The ID of the realm, as a hex string, that the token was made valid for
  <KEY>      The key, as a hex string, that the token was signed with
  <VERSION>  The integer version of the signing key

Options:
  -h, --help  Print help
```
