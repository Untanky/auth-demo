const API_URL = 'http://localhost:8080';
const NEXT_STEP_HEADER = 'Next-Step';

async function signUp() {
  const identifier = document.getElementById('identifier').value;
  const rawResponse = await fetch(
    `${API_URL}/authenticate`, 
    {
      method: 'POST',
      body: { Identifier: identifier },
    }
  );

  const response = await rawResponse.json();
  const nextStep = rawResponse.headers.get(NEXT_STEP_HEADER);
  console.log(nextStep);
  const registering = nextStep === 'register';

  if (registering) {
    const creds = await navigator.credentials.create({ publicKey: {
      ...response,
      challenge: Uint8Array.from(response.challenge, c => c.charCodeAt(0)),
      user: {
        ...response.user,
        id: Uint8Array.from(response.user.id, c => c.charCodeAt(0)),
      }
    } });
    console.log(creds);
  } else {
    const creds = await navigator.credentials.get({

    });
    console.log(creds);
  }
}