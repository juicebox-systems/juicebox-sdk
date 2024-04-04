import React, { useState } from 'react'
import { Buffer } from 'buffer'

const { Client, Configuration, RegisterError, DeleteError, RecoverErrorReason, AuthTokenGenerator } = await import('juicebox-sdk');

export const Demo = () => {
  const [configJSON, setConfigJSON] = useState(`{
  "realms": [
    {
      "id": "9f105f0bf34461034df2ba67b17e5f43",
      "address": "https://gcp.realms.juicebox.xyz/"
    },
    {
      "id": "7546bca7074dd6af64a3c230f04ef803",
      "address": "https://aws.realms.juicebox.xyz/"
    },
    {
      "id": "44e18495c18a3c459954d73d2689e839",
      "public_key": "f6ce077e253010a45101f299a22748cb613a83bd69458e4c3fd36bffdc3c066a",
      "address": "https://lb.juicebox.xyz/"
    }
  ],
  "register_threshold": 3,
  "recover_threshold": 3,
  "pin_hashing_mode": "Standard2019"
}`);

  const [authTokensGeneratorJSON, setAuthTokensGeneratorJSON] = useState(`{
  "key": "302e020100300506032b65700422042070f4086a565233bd57bb577ddf7966d9d506e98e459eba6b4c521f04dd0f9d9c",
  "tenant": "juiceboxdemo",
  "version": 2
}`);
  const [authTokensMapJSON, setAuthTokensMapJSON] = useState(`{"realmId": "token"}`);
  const authTokensJSON = () => authMode === 'generator' ? authTokensGeneratorJSON : authTokensMapJSON;
  const setAuthTokensJSON = json => authMode === 'generator' ? setAuthTokensGeneratorJSON(json) : setAuthTokensMapJSON(json);
  const [authMode, setAuthMode] = useState('generator'); // 'generator' or 'map'

  const [pin, setPin] = useState('1234');
  const [info, setInfo] = useState('apollo');
  const [secret, setSecret] = useState('artemis');
  const [allowedGuesses, setAllowedGuesses] = useState(2);
  const [output, setOutput] = useState('');
  const [isOperationInProgress, setOperationInProgress] = useState(false);

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();


  window.JuiceboxGetAuthToken = async (realmId) => {
    const realmIdString = Buffer.from(realmId).toString('hex');
    if (authMode === 'generator') {
      const generator = new AuthTokenGenerator(authTokensGeneratorJSON);
      return generator.vend(realmIdString, realmIdString);
    } else {
      const authTokens = JSON.parse(authTokensMapJSON);
      return authTokens[realmIdString];
    }
  }

  const createClient = () => {
    try {
      const client = new Client(
        new Configuration(configJSON),
        []
      );

      return client;
    } catch (error) {
      setOutput('Invalid Configuration');
    }
  };

  const handleRegister = async () => {
    const client = createClient();
    if (client == undefined) return;
    setOperationInProgress(true);
    setOutput('Registering...');
    client.register(encoder.encode(pin), encoder.encode(secret), encoder.encode(info), allowedGuesses).then(() => {
      setOutput('Registered Successfully');
      setOperationInProgress(false);
    }).catch(e => {
      setOutput(`Registration Failed (${RegisterError[e]})`);
      setOperationInProgress(false);
    });
  };

  const handleRecover = () => {
    const client = createClient();
    if (client == undefined) return;
    setOperationInProgress(true);
    setOutput('Recovering...');
    client.recover(encoder.encode(pin), encoder.encode(info)).then(secret => {
      setOutput(`Recovered Successfully: ${decoder.decode(secret)}`);
      setOperationInProgress(false);
    }).catch(e => {
      setOutput(`Recover Failed (${RecoverErrorReason[e.reason]}, guessesRemaining: ${e.guesses_remaining})`);
      setOperationInProgress(false);
    });
  };

  const handleDelete = () => {
    const client = createClient();
    if (client == undefined) return;
    setOperationInProgress(true);
    setOutput('Deleting...');
    client.delete().then(() => {
      setOutput('Deleted Successfully');
      setOperationInProgress(false);
    }).catch(e => {
      setOutput(`Delete Failed (${DeleteError[e]})`);
      setOperationInProgress(false);
    });
  };

  return (
    <div>
      <div>
        <label>Config (JSON):</label>
      </div>
      <div>
        <textarea rows={20} cols={90} value={configJSON} onChange={(e) => setConfigJSON(e.target.value)} />
      </div>
      <div>
        <label>Auth Tokens (JSON):</label>
        <span>
          <input type="radio" id="generator" name="authMode" value="generator" checked={authMode === 'generator'} onChange={() => setAuthMode('generator')} />
          <label>Token Generator</label>
        </span>
        <span>
          <input type="radio" id="map" name="authMode" value="map" checked={authMode === 'map'} onChange={() => setAuthMode('map')} />
          <label>Token Map</label>
        </span>
      </div>
      <div>
        <textarea rows={5} cols={110} value={authTokensJSON()} onChange={(e) => setAuthTokensJSON(e.target.value)} />
      </div>
      <div>
        <label>PIN:</label>
      </div>
      <div>
        <input type="text" value={pin} onChange={(e) => setPin(e.target.value)} />
      </div>
      <div>
        <label>Info:</label>
      </div>
      <div>
        <input type="text" value={info} onChange={(e) => setInfo(e.target.value)} />
      </div>
      <div>
        <label>Secret:</label>
      </div>
      <div>
        <input type="text" value={secret} onChange={(e) => setSecret(e.target.value)} />
      </div>
      <div>
        <label>Allowed Guesses:</label>
      </div>
      <div>
        <input type="text" value={allowedGuesses} onChange={(e) => setAllowedGuesses(e.target.value)} />
      </div>
      <div>
        <button onClick={handleRegister} disabled={isOperationInProgress}>Register</button>
        <button onClick={handleRecover} disabled={isOperationInProgress}>Recover</button>
        <button onClick={handleDelete} disabled={isOperationInProgress}>Delete</button>
      </div>
      <div>
        <p>{output}</p>
      </div>
    </div>
  );
};
