#!/usr/bin/env ts-node

import assert from 'assert';
import { Command } from 'commander';
import fs from 'fs';
import https from 'https';
import { Client, Configuration, RecoverError, RecoverErrorReason } from 'juicebox-sdk';
import { Headers, Request, Response } from 'node-fetch';
import fetch from 'node-fetch';

// polyfill fetch, juicebox-sdk expects to be run in a browser

// @ts-ignore
globalThis.Request = Request;
// @ts-ignore
globalThis.Headers = Headers;
// @ts-ignore
globalThis.Response = Response;

async function main() {
    const program = new Command();
    program
        .requiredOption('-c, --configuration <value>', 'The configuration for the client SDK, in JSON format')
        .requiredOption('-a, --auth-tokens <value>', 'The auth token for the client SDK, as a JSON string mapping realm ID to base64-encoded JWT')
        .option('-t, --tls-certificate <value>', 'The path to the TLS certificate used by the realms in DER format')
        .parse(process.argv);

    const options = program.opts();

    const configuration = new Configuration(program.opts().configuration);

    if (options.tlsCertificate != null) {
        const ca = '-----BEGIN CERTIFICATE-----\n'
            + fs.readFileSync(options.tlsCertificate).toString('base64')
            + '\n-----END CERTIFICATE-----';
        const agent = new https.Agent({ ca });

        // @ts-ignore
        globalThis.fetch = (url, options) => fetch(url, { ...options, agent });
    } else {
        // @ts-ignore
        globalThis.fetch = fetch;
    }

    const client = new Client(configuration, []);

    const authTokens = JSON.parse(program.opts().authTokens);

    // @ts-ignore
    globalThis.JuiceboxGetAuthToken = async (realmId) => {
        return authTokens[Buffer.from(realmId).toString('hex')];
    };

    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    console.log("[JavaScript] Starting register (allowing 2 guesses)");
    await client.register(encoder.encode("1234"), encoder.encode("apollo"), 2);
    console.log("[JavaScript] Register succeeded");

    console.log("[JavaScript] Starting recover with wrong PIN (guess 1)");
    try {
        const secret = await client.recover(encoder.encode("4321"));
        assert.fail("[JavaScript] Recover unexpectedly succeeded with secret: " + decoder.decode(secret));
    } catch (error) {
        if (error instanceof RecoverError && error.reason === RecoverErrorReason.InvalidPin) {
            assert.strictEqual(error.guesses_remaining, 1);
            console.log("[JavaScript] Recover expectedly unsuccessful");
        } else {
            assert.fail("[JavaScript] Recover failed with unexpected error: " + error);
        }
    }

    console.log("[JavaScript] Starting recover with correct PIN (guess 2)");
    const secret1 = await client.recover(encoder.encode("1234"));
    console.log("[JavaScript] Recovered secret: " + decoder.decode(secret1));

    console.log("[JavaScript] Starting recover with wrong PIN (guess 1)");
    try {
        const secret = await client.recover(encoder.encode("4321"));
        assert.fail("[JavaScript] Recover unexpectedly succeeded with secret: " + decoder.decode(secret));
    } catch (error) {
        if (error instanceof RecoverError && error.reason === RecoverErrorReason.InvalidPin) {
            assert.strictEqual(error.guesses_remaining, 1);
            console.log("[JavaScript] Recover expectedly unsuccessful");
        } else {
            assert.fail("[JavaScript] Recover failed with unexpected error: " + error);
        }
    }

    console.log("[JavaScript] Starting recover with wrong PIN (guess 2)");
    try {
        const secret = await client.recover(encoder.encode("4321"));
        assert.fail("[JavaScript] Recover unexpectedly succeeded with secret: " + decoder.decode(secret));
    } catch (error) {
        if (error instanceof RecoverError && error.reason === RecoverErrorReason.InvalidPin) {
            assert.strictEqual(error.guesses_remaining, 0);
            console.log("[JavaScript] Recover expectedly unsuccessful");
        } else {
            assert.fail("[JavaScript] Recover failed with unexpected error: " + error);
        }
    }

    console.log("[JavaScript] Starting recover with correct PIN (guess 3)");
    try {
        const secret = await client.recover(encoder.encode("1234"));
        assert.fail("[JavaScript] Recover unexpectedly succeeded with secret: " + decoder.decode(secret));
    } catch (error) {
        if (error instanceof RecoverError && error.reason === RecoverErrorReason.InvalidPin) {
            assert.strictEqual(error.guesses_remaining, 0);
            console.log("[JavaScript] Recover expectedly unsuccessful");
        } else {
            assert.fail("[JavaScript] Recover failed with unexpected error: " + error);
        }
    }

    console.log("[JavaScript] Starting register (allowing 2 guesses)");
    await client.register(encoder.encode("abcd"), encoder.encode("artemis"), 2);
    console.log("[JavaScript] Register succeeded");

    console.log("[JavaScript] Starting recover with wrong PIN (guess 1)");
    try {
        const secret = await client.recover(encoder.encode("zyxw"));
        assert.fail("[JavaScript] Recover unexpectedly succeeded with secret: " + decoder.decode(secret));
    } catch (error) {
        if (error instanceof RecoverError && error.reason === RecoverErrorReason.InvalidPin) {
            assert.strictEqual(error.guesses_remaining, 1);
            console.log("[JavaScript] Recover expectedly unsuccessful");
        } else {
            assert.fail("[JavaScript] Recover failed with unexpected error: " + error);
        }
    }

    console.log("[JavaScript] Starting recover with correct PIN (guess 2)");
    const secret2 = await client.recover(encoder.encode("abcd"));
    console.log("[JavaScript] Recovered secret: " + decoder.decode(secret2));

    console.log("[JavaScript] Deleting secret");
    await client.delete();
    console.log("[JavaScript] Deleting succeeded");

    console.log("[JavaScript] Starting recover with correct PIN after delete");
    try {
        const secret = await client.recover(encoder.encode("abcd"));
        assert.fail("[JavaScript] Recover unexpectedly succeeded with secret: " + decoder.decode(secret));
    } catch (error) {
        if (error instanceof RecoverError && error.reason === RecoverErrorReason.NotRegistered) {
            console.log("[JavaScript] Recover expectedly unsuccessful");
        } else {
            assert.fail("[JavaScript] Recover failed with unexpected error: " + error);
        }
    }
}

main();
