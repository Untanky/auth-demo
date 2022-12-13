const BASE_URL = '';
const AUTHENTICATE_URL = `${BASE_URL}/authenticate`;

const bufferEncode = (value: Uint8Array): string => {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");;
}

export const authenticate = async (identifier: string): Promise<void> => {
  const body = JSON.stringify({ identifier });
  const response = await fetch(
    AUTHENTICATE_URL, 
    {
      method: 'POST', 
      headers: {
        'Content-Type': 'application/json',
      },
      body
    }
  );

  const credentialsParams = await response.json();
  const nextStep = response.headers.get('Next-Step');
  const registering = nextStep === 'register';

  if (registering) {
    register(credentialsParams);
  } else {
    login(credentialsParams);
  }
}

const register = async (createOptions: PublicKeyCredentialCreationOptions): Promise<void> => {
  const credential = await navigator.credentials.create({
    publicKey: createOptions
  });

  // @ts-ignore
  if (credential.response instanceof AuthenticatorAttestationResponse) {
    // @ts-ignore
    const body = { id: credential.id, type: credential.type, rawId: bufferEncode(credential.rawId), response: { attestationObject: bufferEncode(credential.response.attestationObject), clientDataJSON: bufferEncode(credential.response.clientDataJSON) } };
  
    await fetch(`${AUTHENTICATE_URL}/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  } else {
    throw new Error('Unknown error');
  }
}

const login = async (requestOptions: PublicKeyCredentialRequestOptions): Promise<void> => {
  const assertion = await navigator.credentials.get({
    publicKey: requestOptions
  });

        // @ts-ignore
  if (assertion.response instanceof AuthenticatorAssertionResponse) {
    const body = { 
      id: assertion.id,
      // @ts-ignore
      rawId: bufferEncode(assertion.rawId),
      type: assertion.type,
      response: {
        // @ts-ignore
        authenticatorData: bufferEncode(assertion.response.authenticatorData),
        // @ts-ignore
        clientDataJSON: bufferEncode(assertion.response.clientDataJSON),
        // @ts-ignore
        signature: bufferEncode(assertion.response.signature),
        // @ts-ignore
        userHandle: bufferEncode(assertion.response.userHandle),
      }
    };

    await fetch(`${AUTHENTICATE_URL}/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  } else {
    throw new Error('Error');
  }
}