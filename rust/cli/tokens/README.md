# Tokens

A CLI tool for validation and creation of auth tokens. While you likely will want to integrate token creation into your server, this tool allows for quickly generating canonical tokens to validate your implementation against or to use for testing purposes. Additionally, it supports validating tokens created by other means to verify they match the expected format.

This tool can be built with:
```
cargo build -p juicebox_tokens_cli
```

```
Usage: tokens <COMMAND>

Commands:
  create    Create an auth token for a tenant
  validate  Validate an auth token for a tenant
  random    Create a random key (or key pair) for a tenant and output to stdout
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

# Create

Create an auth token for a given tenant.

```
Usage: tokens create [OPTIONS] --user <USER> --tenant <TENANT> --realm <REALM> --key <KEY> --version <VERSION> --algorithm <ALGORITHM>

Options:
  -u, --user <USER>            An alphanumeric user ID that this token should be valid for
  -t, --tenant <TENANT>        An alphanumeric tenant ID
  -r, --realm <REALM>          The ID of the realm, as a hex string, that the token should be valid for
  -k, --key <KEY>              The key, as a hex string, that the token should be signed with
  -v, --version <VERSION>      The integer version of the signing key
  -a, --algorithm <ALGORITHM>  The algorithm of the signing key [possible values: RS256, HS256, EdDSA]
  -s, --scope <SCOPE>          The scope to include in the token [default: user]
  -h, --help                   Print help (see more with '--help')
```

# Validate

Validate an auth token for a tenant. Specific errors and warnings will be printed to help you diagnose any issues with your token creation code.

```
Usage: tokens validate --token <TOKEN> --user <USER> --tenant <TENANT> --realm <REALM> --key <KEY> --version <VERSION> --algorithm <ALGORITHM>

Options:
  -j, --token <TOKEN>          The jwt token to validate
  -u, --user <USER>            The alphanumeric user ID that this token was created with
  -t, --tenant <TENANT>        The alphanumeric tenant ID that this token was created with
  -r, --realm <REALM>          The ID of the realm, as a hex string, that the token was made valid for
  -k, --key <KEY>              The key, as a hex string, that the token was signed with
  -v, --version <VERSION>      The integer version of the signing key
  -a, --algorithm <ALGORITHM>  The algorithm of the signing key [possible values: RS256, HS256, EdDSA]
  -h, --help                   Print help (see more with '--help')
```

# Random

Generate a random signing key (or key pair for asymmetric algorithms) to use for token creation and validation.

The generated key will be output to stdout.

```
Usage: tokens random --algorithm <ALGORITHM>

Options:
  -a, --algorithm <ALGORITHM>  The algorithm of the signing key [possible values: RS256, HS256, EdDSA]
  -h, --help                   Print help (see more with '--help')
```
