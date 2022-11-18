async function signUp() {
  const creds = await navigator.credentials.create({
    publicKey: {
        challenge: Uint8Array.from(
            'abcdefghij', c => c.charCodeAt(0)),
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
            authenticatorAttachment: "cross-platform",
        },
        timeout: 60000,
        attestation: "direct"
    }
  });

  const textDecoder = new TextDecoder('utf-8');
  console.log(creds);
  console.log(textDecoder.decode(creds.response.clientDataJSON));
}