const BASE_URL = import.meta.env.VITE_URL || 'http://localhost:8080/api/webauthn/v1';
const AUTHENTICATE_URL = `${BASE_URL}`;

const bufferEncode = (value: Uint8Array): string => {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(value)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");;
}

interface AuthenticationResponse {
  accessKey: string;
}

export const authenticate = async (identifier: string): Promise<AuthenticationResponse> => {
  const challenge = new URLSearchParams(window.location.search).get('challenge');
  const body = JSON.stringify({ identifier, challenge });
  const response = await fetch(
    `${AUTHENTICATE_URL}/init`, 
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
    await register(credentialsParams);
  } else {
    await login(credentialsParams);
  }

  return {
    accessKey: ''
  };
}

const register = async (createOptions: PublicKeyCredentialCreationOptions): Promise<void> => {
  const credential = await navigator.credentials.create({
    publicKey: {
      ...createOptions,
      // @ts-ignore
      challenge: Uint8Array.from(createOptions.challenge, c => c.charCodeAt(0)),
      user: {
        ...createOptions.user,
        // @ts-ignore
        id: Uint8Array.from(createOptions.user.id, c => c.charCodeAt(0)),
      }
    }
  });

  // @ts-ignore
  if (credential.response instanceof AuthenticatorAttestationResponse) {
    // @ts-ignore
    const body = { id: credential.id, type: credential.type, rawId: bufferEncode(credential.rawId), response: { attestationObject: bufferEncode(credential.response.attestationObject), clientDataJSON: bufferEncode(credential.response.clientDataJSON) } };
  
    await fetch(`${AUTHENTICATE_URL}/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then((response) => {
      if (response.redirected) {
          window.location.href = response.url;
      }
    });
  } else {
    throw new Error('Unknown error');
  }
}

const login = async (requestOptions: PublicKeyCredentialRequestOptions): Promise<void> => {
  const assertion = await navigator.credentials.get({
    publicKey: {
        ...requestOptions,
        // @ts-ignore
        challenge: Uint8Array.from(requestOptions.challenge, c => c.charCodeAt(0)),
        allowCredentials: requestOptions.allowCredentials.map((credentials) => ({
          ...credentials,
          // @ts-ignore
          id: Uint8Array.from(atob(credentials.id), c => c.charCodeAt(0)),
          transports: []
        }))
      }
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

    await fetch(`${AUTHENTICATE_URL}/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then((response) => {
      if (response.redirected) {
          window.location.href = response.url;
      }
    });
  } else {
    throw new Error('Error');
  }
}