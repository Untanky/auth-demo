const API_URL = 'http://localhost:8080'

async function signUp() {
  const identifier = document.getElementById('identifier').value;

  console.log(identifier);

  const rawResponse = await fetch(
    `${API_URL}/challenge`, 
    {
      method: 'POST',
      body: { Identifier: identifier },
    }
  );

  const response = await rawResponse.json();
  console.log(response);

  const creds = await navigator.credentials.create({
    publicKey: {
        challenge: Uint8Array.from(
            response.Challenge, c => c.charCodeAt(0)),
        rp: {
            name: "IAM Auth",
            id: 'localhost'
        },
        user: {
            id: Uint8Array.from(
                "UZSL85T9AFC", c => c.charCodeAt(0)),
            name: "lukas.grimm@mail.de",
            displayName: "Untanky",
        },
        pubKeyCredParams: [{alg: -7, type: "public-key"}],
        authenticatorSelection: {
            authenticatorAttachment: 'both',
        },
        timeout: 60000,
        attestation: "direct"
    }
  });
}