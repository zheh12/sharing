- [Sui ZkLogin Introduction](#org72daff4)
  - [The Sui blockchain](#org54d684b)
  - [Signatures](#org77aedaa)
  - [ZkLogin](#org428e673)
    - [the complete zkLogin Flow](#org747fb93)
    - [Entities](#org46e8962)
  - [Sui zkLogin vs Polygon Did vs Fireblocks Ncw](#org507ebca)


<a id="org72daff4"></a>

# Sui ZkLogin Introduction


<a id="org54d684b"></a>

## The Sui blockchain

Sui is defined as a Layer 1 protocol blockchain. In basic terms, this means that Sui performs its own consensus and validation for transaction blocks (activity) on its networks using its own native token (SUI).


<a id="org77aedaa"></a>

## Signatures

When a user submits a signed transaction, a serialized signature and a serialized transaction data is submitted. The serialized transaction data is the BCS serialized bytes of the struct TransactionData and the serialized signature is defined as a concatenation of bytes of flag || sig || pk.

The flag is a 1-byte representation corresponding to the signature scheme that the signer chooses. The following table lists each signing scheme and its corresponding flag:

| Scheme           | Flag |
|---------------- |---- |
| Ed25519 Pure     | 0x00 |
| EDCDSA Secp256k1 | 0x01 |
| EDCDSA Secp256r1 | 0x02 |
| multisig         | 0x03 |
| zkLogin          | 0x05 |


<a id="org428e673"></a>

## ZkLogin

ZkLogin is a Sui primitive that provides the ability for you to send transactions from a Sui address using an OAuth credential, without publicly linking the two.

zkLogin is designed with the following goals in mind:

-   Streamlined onboarding: zkLogin enables you to transact on Sui using the familiar OAuth login flow, eliminating the friction of handling cryptographic keys or remembering mnemonics.
-   Self-custody: A zkLogin transaction requires user approval via the standard OAuth login process&#x2013;the OAuth provider cannot transact on the user's behalf.
-   Security: zkLogin is a two-factor authentication scheme; sending a transaction requires both a credential from a recent OAuth login and a salt not managed by the OAuth provider. An attacker who compromises an OAuth account cannot transact from the user's corresponding Sui address unless they separately compromise the salt.
-   Privacy: Zero-knowledge proofs prevent third parties from linking a Sui address with its corresponding OAuth identifier.
-   Optional verified identity: A user can opt in to verify the OAuth identifier that was used to derive a particular Sui address. This serves as the foundation for a verifiable on-chain identity layer.
-   Accessibility: zkLogin is one of several native Sui signature schemes thanks to Sui's cryptography agility. It integrates with other Sui primitives, like sponsored transactions and multisig.
-   Rigorousness: The code for zkLogin has been independently audited by two firms specializing in zero knowledge. The public zkLogin ceremony for creating the common reference string attracted contributions from more than 100 participants.


<a id="org747fb93"></a>

### the complete zkLogin Flow

![img](Sui_ZkLogin_Introduction/2024-11-17_11-38-48_zkLogin.png) (Step 0) We use Groth16 for our protocol’s zkSNARK instantiation, requiring a singular generation of a structured common reference string (CRS) linked to the circuit. A ceremony is conducted to generate the CRS, which is used to produce the proving key in the ZK Proving Service, the verifying key in Sui Authority.

(Step 1) Generate Ephemeral Key Pair (eph<sub>sk</sub>, eph<sub>pk</sub>). The ephemeral key pair is used to sign the TransactionBlock. Store in the browser session. (Session Storage)

```js
// PrivateKey
{"schema":"ED25519","privateKey":"3tYumE6Nq2SPsy+Y/WGtRMCCUhvEDw19HfqVrg4mFjU="}
// PublicKey:
"dFE3jQlT9d6paYYwwyN685SoubedBWhIcMJBSS5BQXo="
```

(Step 2) Fetch JWT(from OpenID Provider) Require parameters:

1.  `$CLIENT_ID` (Obtained by applying for OpenID Service.)
2.  `$REDIRECT_URL` (App Url, configured in OpenID Service)
3.  $NONCE (Generated through ephemeralKeyPair, maxEpoch, randomness)
4.  ephemeralKeyPair: Ephemeral key pair generated in the step 1
5.  maxEpoch: Validity period of the ephemeral key pair
6.  randomness: Randomness

We can fetch current Epoch via Sui Client, su as it’s 61 Assuming the validity period is set to 10 Epochs, then maxEpoch: 71 we can generate randomness:

```js
  ​​
import { generateRandomness } from '@mysten/zklogin';

// randomness
const randomness = generateRandomness();
```

randomness: 231517808180551391891007165132990504424

```js
import { generateNonce } from "@mysten/zklogin";

// Generate Nonce for acquiring JWT:
const nonce = generateNonce(
  ephemeralKeyPair.getPublicKey(),
  maxEpoch,
  randomness
);

```

so we can get nonce: ly2KYOS6cyriaGNYlQ9l3GHxj98

(Step 3) Get and Decode JWT (needed for assembling zKLogin signature later)

So we can get the `id_token` and decode it to JWT payload

```js
// id_token Header.Payload.Signature
"eyJhbGciOiJSUzI1NiIsImtpZCI6IjFkYzBmMTcyZThkNmVmMzgyZDZkM2EyMzFmNmMxOTdkZDY4Y2U1ZWYiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiI1NzMxMjAwNzA4NzEtMGs3Z2E2bnM3OWllMGpwZzFlaTZpcDV2amUyb3N0dDYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiI1NzMxMjAwNzA4NzEtMGs3Z2E2bnM3OWllMGpwZzFlaTZpcDV2amUyb3N0dDYuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDYwMDgyOTIzNjcyNTMyNzI2NDQiLCJub25jZSI6Imx5MktZT1M2Y3lyaWFHTllsUTlsM0dIeGo5OCIsIm5iZiI6MTczMTU2OTk4NiwiaWF0IjoxNzMxNTcwMjg2LCJleHAiOjE3MzE1NzM4ODYsImp0aSI6IjY1ZjhlMzE1NWM0NWNkYmViMjBmODBmZDliYzhlMzQ0NzYyZDEwYzcifQ.GQXSw0YlP6BBrQOb_4zTojZ6MuShmuzn7ZJh-3cQhw0KYX2W5X8NlGodJvVUfLHqlwoX4lN1Gf-J0_3Qjui9A0Unr4f7PGLJnlitrd_3m7Ea2M9c-WSgV8801qh-7oupHwNRF9WpeHV6TWQ9sQVfg0s33DKsYKmnN6XRM1VN1igAdd_uxFmRrzOKc4cpFQSi_9urFTWxnMCxwvNtFizq55NpTQl090NbAQs4mdceb-z9VnqixQa_ACdm2OqUHkR7vvoRor9alHEaWMB6a7Gxc9xvSznfSVQZUKYCVmql4mcsdpApJi40aCaqskhual99ckl-Q0FSAOhpMG8Id1Y5Xw"

import { JwtPayload, jwtDecode } from "jwt-decode";

const jwtPayload = jwtDecode(id_token);
const decodedJwt = jwt_decode(jwtPayload) as JwtPayload;
// JWT Payload
{
  "iss": "https://accounts.google.com",
  "azp": "573120070871-0k7ga6ns79ie0jpg1ei6ip5vje2ostt6.apps.googleusercontent.com",
  "aud": "573120070871-0k7ga6ns79ie0jpg1ei6ip5vje2ostt6.apps.googleusercontent.com",
  "sub": "106008292367253272644",
  "nonce": "ly2KYOS6cyriaGNYlQ9l3GHxj98",
  "nbf": 1731569986,
  "iat": 1731570286,
  "exp": 1731573886,
  "jti": "65f8e3155c45cdbeb20f80fd9bc8e344762d10c7"
}
```

iss (issuer): Issuer aud(audience): JWT Consumer (CLIENT<sub>ID</sub>) sub(subject): Subject (user identifier, unique for each user) nonce: Signature order(values generated by assembling URL parameters earlier) nbf (Not Before): Issued At iat(Issued At): Issued Time exp(expiration time): Expiration Time jti(JWT ID): JWT ID

(Step 4-5) Generate User's Salt

User Salt is used to eliminate the one-to-one correspondence between the OAuth identifier(sub) and the on-chain Sui address, avoiding linking Web2 credentials with Web3 credentials.

Therefore, it is essential to safeguard the Salt. If lost, users won't be able to recover the address generated with the current Salt.

The salt is unique based on iss,aud,sub upon validation of the JWT.

User Salt: 48516934399074529949122746775580145793

(Step 6-7) Fetch ZK Proof (Groth16) This is the proof (ZK Proof) for the ephemeral key pair, used to demonstrate the validity of the ephemeral key pair.

The user sends the ZK proving service the JWT, user salt, ephemeral public key, jwt randomness, key claim name (i.e. sub). The proving service generates a Zero-Knowledge Proof that takes as private inputs and does the following:

1.  Checks the nonce is derived correctly as defined
2.  Checks that key claim value matches the corresponding field in the JWT
3.  Verifies the RSA signature from OP(OpenID Provider) on the JWT
4.  The address is consistent with the key claim value and user salt

```js
const zkProofResult = await axios.post(
    "https://prover-dev.mystenlabs.com/v1",
    {
        jwt: oauthParams?.id_token as string,
        extendedEphemeralPublicKey: extendedEphemeralPublicKey,
        maxEpoch: maxEpoch,
        jwtRandomness: randomness,
        salt: userSalt,
        keyClaimName: "sub",
    },
    {
        headers: {
            "Content-Type": "application/json",
        },
    }
).data;
```

Proof Results:

```js
{
  "proofPoints": {
    "a": [
      "3525062626418970747499393007232416691443379703891088370690682725086678319164",
      "5700184620676217196822847941599608247158300331959795779596479562015784206189",
      "1"
    ],
    "b": [
      [
        "5442191657060540940700133709820605726134904999193509297138551917358635821358",
        "5255511844670804738594305696401250802779762634363789278506046713555390135252"
      ],
      [
        "19187572160206632209322348078814416009802068469346941991418995952661292420549",
        "16333425071670130555113695152030248628825763380229357578447076279877157398048"
      ],
      [
        "1",
        "0"
      ]
    ],
    "c": [
      "3160791984214921668507715993928470630290926423770774507180281672127854258400",
      "1527855699933846238951333722223847994147275875573586506296066325337951391238",
      "1"
    ]
  },
  "issBase64Details": {
    "value": "yJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLC",
    "indexMod4": 1
  },
  "headerBase64": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFkYzBmMTcyZThkNmVmMzgyZDZkM2EyMzFmNmMxOTdkZDY4Y2U1ZWYiLCJ0eXAiOiJKV1QifQ"
}
```

(Step 8) Generate User's Sui address The user’s Sui address is determined by sub, iss, aud and user<sub>salt</sub> together. For the same JWT, sub, iss and aud will not change with each login.

The address is computed on the following inputs:

1.  The address flag: `zk_login_flag` = 0x05 for zkLogin address. This serves as a domain separator as a signature scheme defined in crypto agility.
2.  `kc_name_F` = hashBytesToField(`kc_name`, maxKCNameLen): Name of the key claim, e.g., sub. THe sequence of bytes is mapped to a field element in BN254 using hashBytesToField
3.  `kc_value_F` = hashBytesToField(`kc_value`, maxKCValueLen): The value of the key claim mapped using hashBytesToField.
4.  `aud_F` = hashBytesToField(aud, maxAudValueLen): The relying party (RP) identifier.
5.  iss: The OpenID Provider (OP) identifier.
6.  `user_salt`: A value introduced to unlink the OAuth identifier with the on-chain address.

Finally, we derive `zk_login_address` = `Blake2b_256` (`zk_login_flag`, `iss_L`, iss, `addr_seed`) where `addr_seed` = `Poseidon_BN254` (`kc_name_F`, `kc_value_F`, `aud_F`, `Poseidon_BN254` (`user_salt`).

User Sui Address: 0x7be17b6ce9a63e1a002ec6a85921d58eb8290ed982f3ed554ebd02ccd572063f

(Step 9-10) Assemble zkLogin signature and submit the transaction. A transaction is signed using the ephemeral private key to generate an ephemeral signature. Finally, the user submits the transaction along with the ephemeral signature, ZK proof and other inputs to Sui.

```js
const txb = new TransactionBlock();

// Transfer 1 SUI to 0xfa0f...8a36.
const [coin] = txb.splitCoins(txb.gas,[MIST_PER_SUI * 1n]);
txb.transferObjects(
    [coin],
    "0xfa0f8542f256e669694624aa3ee7bfbde5af54641646a3a05924cf9e329a8a36"
);
txb.setSender(zkLoginUserAddress);

const { bytes, signature: userSignature } = await txb.sign({
    client,
    signer: ephemeralKeyPair
});

// Generate addressSeed using userSalt, sub, and aud (JWT Payload)
// as parameters for obtaining zkLoginSignature
const addressSeed: string = genAddressSeed(
    BigInt(userSalt),
    "sub",
    decodedJwt.sub,
    decodedJwt.aud
).toString();

// partialZkLoginSignature()
const zkLoginSignature: SerializedSignature = getZkLoginSignature({
    inputs: {
        ...partialZkLoginSignature,
        addressSeed,
    },
    maxEpoch,
    userSignature,
});

// Execute transaction
suiClient.executeTransactionBlock({
    transactionBlock: bytes,
    signature: zkLoginSignature,
});
```

(After Step 10) After submitted on chain, Sui Authorities verify the ZK proof against the provider JWKs from storage (agreed upon in consensus) and also the ephemeral signature.

Execution successful: BGZni1cGMeAu4nPPETQdstDiYPoctu6TnL3u5sb9X2Dy (transaction hash)


<a id="org46e8962"></a>

### Entities

1.  Application frontend: This describes the wallet or frontend application that supports zkLogin. This frontend is responsible for storing the ephemeral private key, directing users to complete the OAuth login flow, creating and signing a zkLogin transaction.
2.  Salt Backup Service: This is a backend service responsible for returning a salt per unique user. There are several options for the applications to maintain the user salt:
    1.  Client side:
        1.  Option 1: Request user input for the salt during wallet access,transferring the responsibility to the user, who must then remember it.
        2.  Option 2: Browser or Mobile Storage: Ensure proper workflows to prevent users from losing wallet access during device or browser changes. One approach is to email the salt during the new wallet setup.
    2.  Backend service that exposes an endpoint that returns a unique salt for each user consistently.
        1.  Option 3: Store mapping from user identifier (e.g. sub) to user salt in a conventional database. The salt is unique per user
        2.  Option 4: Implements a service that keeps a master seed value, and derives a user salt with key derivation by validating and parsing the JWT.For example, use HKDF(ikm = seed, salt = iss || aud, info = sub) defined here. Note that this option does not allow any rotation on master seed or change in client ID (i.e. aud), otherwise a different user address will be derived and will result in loss of funds.
3.  ZK Proving Service: This is a backend service responsible for generating ZK proofs based on JWT, JWT randomness, user salt and max epoch. This proof is submitted on-chain along with the ephemeral signature for a zkLogin transaction.


<a id="org507ebca"></a>

## Sui zkLogin vs Polygon Did vs Fireblocks Ncw

Here’s a comparison table for ****Sui zkLogin****, ****Polygon DID****, and ****Fireblocks Networked Custody Wallet (NCW)****.

| Feature                          | Sui zkLogin                                                                    | Polygon DID                                               | Fireblocks NCW                                                   |
|-------------------------------- |------------------------------------------------------------------------------ |--------------------------------------------------------- |---------------------------------------------------------------- |
| ****Purpose****                  | Provides decentralized login and sign transactions using zero-knowledge proofs | Offers decentralized identity and credential verification | Offers secure wallet infrastructure for institutions             |
| ****Authentication Mechanism**** | Zero-Knowledge Proofs (zk-SNARKs)                                              | DID (Decentralized Identifier) standard                   | Multi-party computation (MPC) and secure wallet setup            |
| ****Target Users****             | Developers, dApps requiring secure, privacy-oriented login and web2 experiance | Developers, apps needing identity verification            | Institutional investors, asset managers, enterprises             |
| ****Privacy Focus****            | High (uses zk-SNARKs for user privacy)                                         | Moderate (privacy in credential sharing)                  | Moderate (focus on security and compliance)                      |
| ****Blockchain Compatibility**** | Sui blockchain                                                                 | Ethereum (Polygon network), EVM-compatible chains         | Supports multiple blockchains                                    |
| ****Use Case Examples****        | User login, anonymous data access, sign transactions                           | Verifiable credentials, identity management               | Custody, staking, DeFi access for institutional funds            |
| ****Integration Ease****         | SDKs and APIs available for Sui                                                | Compatible with standard DID protocols                    | API and SDK for enterprise-level integration                     |
| ****Security****                 | High, with cryptographic privacy and security                                  | Secure but relies on DID standards                        | Very high, with multi-layered security architecture              |
| ****Compliance Features****      | Minimal focus on regulatory compliance                                         | Limited compliance, depending on app use                  | High compliance with institutional regulatory standards          |
| ****Cost Consideration****       | May involve transaction fees on Sui                                            | Gas fees on Ethereum/Polygon                              | Enterprise-grade pricing, higher costs                           |
| ****Main Advantage****           | Strong privacy with zero-knowledge tech                                        | Interoperability with DID standards                       | Robust security and custody features for institutions            |
| ****Main Limitation****          | Limited to Sui ecosystem                                                       | Mostly limited to EVM-based chains                        | Primarily for institutional clients, less suited for general use |
