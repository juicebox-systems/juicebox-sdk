import React, { useState } from 'react'
import { Buffer } from 'buffer'

const { Client, Configuration, RegisterError, DeleteError, RecoverErrorReason } = await import('juicebox-sdk');

export const Demo = () => {
  const [configJSON, setConfigJSON] = useState('{"realms":[], "register_threshold": 1, "recover_threshold": 1, "pin_hashing_mode": "Standard2019"}');
  const [authTokensJSON, setAuthTokensJSON] = useState('{"realmId": "token"}');
  const [pin, setPin] = useState('1234');
  const [info, setInfo] = useState('info');
  const [secret, setSecret] = useState('secret');
  const [allowedGuesses, setAllowedGuesses] = useState(2);
  const [output, setOutput] = useState('');
  const [isOperationInProgress, setOperationInProgress] = useState(false);

  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  window.JuiceboxGetAuthToken = async (realmId) => {
    const authTokens = JSON.parse(authTokensJSON);
    return authTokens[Buffer.from(realmId).toString('hex')];
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
        <textarea rows={8} value={configJSON} onChange={(e) => setConfigJSON(e.target.value)} />
      </div>
      <div>
        <label>API Tokens (JSON):</label>
      </div>
      <div>
        <textarea rows={8} value={authTokensJSON} onChange={(e) => setAuthTokensJSON(e.target.value)} />
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
