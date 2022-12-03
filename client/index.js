const API_URL = 'http://localhost:8080/authenticate/';
const NEXT_STEP_HEADER = 'Next-Step';

function bufferEncode(value) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");;
}

async function signUp() {
  const identifier = document.getElementById('identifier').value;
  const rawResponse = await fetch(
    `${API_URL}`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ Identifier: identifier }),
    }
  );

  const credentialsParams = await rawResponse.json();
  const nextStep = rawResponse.headers.get(NEXT_STEP_HEADER);
  const registering = nextStep === 'register';

  if (registering) {
    const credential = await navigator.credentials.create({
      publicKey: {
        ...credentialsParams,
        challenge: Uint8Array.from(credentialsParams.challenge, c => c.charCodeAt(0)),
        user: {
          ...credentialsParams.user,
          id: Uint8Array.from(credentialsParams.user.id, c => c.charCodeAt(0)),
        }
      }
    });

    if (credential.response instanceof AuthenticatorAttestationResponse) {
      const body = { id: credential.id, type: credential.type, rawId: bufferEncode(credential.rawId), response: { attestationObject: bufferEncode(credential.response.attestationObject), clientDataJSON: bufferEncode(credential.response.clientDataJSON) } };

      await fetch(`${API_URL}${nextStep}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    } else {
      throw new Error('Error');
    }
  } else {
    const assertion = await navigator.credentials.get({
      publicKey: {
        ...credentialsParams,
        challenge: Uint8Array.from(credentialsParams.challenge, c => c.charCodeAt(0)),
        allowCredentials: credentialsParams.allowCredentials.map((credentials) => ({
          ...credentials,
          id: Uint8Array.from(atob(credentials.id), c => c.charCodeAt(0)),
          transports: []
        }))
      }
    });

    if (assertion.response instanceof AuthenticatorAssertionResponse) {
      const body = { 
        id: assertion.id,
        rawId: bufferEncode(assertion.rawId),
        type: assertion.type,
        response: {
          authenticatorData: bufferEncode(assertion.response.authenticatorData),
          clientDataJSON: bufferEncode(assertion.response.clientDataJSON),
          signature: bufferEncode(assertion.response.signature),
          userHandle: bufferEncode(assertion.response.userHandle),
        }
      };

      await fetch(`${API_URL}${nextStep}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    } else {
      throw new Error('Error');
    }
  }
}