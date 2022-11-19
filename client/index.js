const API_URL = 'http://localhost:8080';
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
    `${API_URL}/authenticate`,
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
      const decoder = new TextDecoder('utf-8');

      const body = { id: credential.id, type: credential.type, rawId: decoder.decode(credential.rawId), response: { attestationObject: decoder.decode(credential.response.attestationObject), clientDataJSON: decoder.decode(credential.response.clientDataJSON) } };

      await fetch(`${API_URL}/${nextStep}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    } else {
      throw new Error('Error');
    }
  } else {
    const creds = await navigator.credentials.get({

    });
  }
}