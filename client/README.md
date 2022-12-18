# WebAuthn Demo

WebAuthn is a specification for password-less authentication on the web. The specification describes an API between a web page and the browser. This API is used to access system or browser specific authentication methods. Furthermore a workflow is described to handle the data provided by the system authenticators.

There are a couple of key term used by the specification:

- Authenticator: party that handles verification that the user is who they claim to be
- Relying Party: resource provider that requires authentication for access
- Subject: user during authentication

The general idea behind WebAuthn is to stop using password when signing up for and signing into services, as weak or stolen password can pose a security risk. A solution to this problem is public key authentication.

In public key authentication, the client generates a key pair, consisting of a private and public key. The public key can be stored at the relying party. The private key can then be used to sign a challenge provided by the relying party. The relying party then can use the public key to verify that the challenge was signed by the correct client.

In traditional password based authentication, the server is the key authenticator, being a focal point of attacks. With WebAuthn the authenticator role is moved to the client, and more specifically the browser or underlying system the client is implemented on. The authenticator has become decentralised.

## Flow of WebAuthn

## Phishing

WebAuthn also eliminates the risk of phishing entirely. The authenticator must not sign the challenge if the origin does not match the requested key. Therefore phishing becomes difficult

## Disadvantages of WebAuthn

While WebAuthn provides great security benefits, especially in a corporate environment, it is somewhat limited by design. Cross-device authentication is a possibility, but can be cumbersome to set up and many users prefer a more stream-lined and “standardised” authentication model. 

Secondly, the authenticators are all implemented either by browser vendors, operating systems or hardware manufacturers. These keys, again by design, cannot be interchanged between these parties. This makes switching from that vendor or manufacturer a difficulty, especially when WebAuthn has been used exclusively.

## Implementation Details

- Backend with Go
- Web Frontend with Svelte