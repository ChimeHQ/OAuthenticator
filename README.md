[![Build Status][build status badge]][build status]
[![Platforms][platforms badge]][platforms]
[![Documentation][documentation badge]][documentation]

# OAuthenticator
Lightweight OAuth 2.0 request authentication in Swift

There are lots of OAuth solutions out there. This one is small, uses Swift concurrency, and offers lots of control over the process.

Features:

- Swift concurrency support
- Fine-grained control over the entire token and refresh flow
- Optional integration with `ASWebAuthenticationSession`
- Control over when and if users are prompted to log into a service
- Preliminary support for PAR, PKCE, Server/Client Metadata, and DPoP

This library currently doesn't have functional JWT or JWK generation, and both are required for DPoP. You must use an external JWT library to do this, connected to the system via the `DPoPSigner.JWTGenerator` function. I have used [jose-swift](https://github.com/beatt83/jose-swift) with success.

There's also built-in support for services to streamline integration:

- GitHub
- Mastodon
- Google API
- Bluesky

If you'd like to contribute a similar thing for another service, please open a PR!

## Integration

Swift Package Manager:

```swift
dependencies: [
    .package(url: "https://github.com/ChimeHQ/OAuthenticator", from: "0.3.0")
]
```

## Usage

The main type is the `Authenticator`. It can execute a `URLRequest` in a similar fashion to `URLSession`, but will handle all authentication requirements and tack on the needed `Authorization` header. Its behavior is controlled via `Authenticator.Configuration` and `URLResponseProvider`. By default, the `URLResponseProvider` will be a private `URLSession`, but you can customize this if needed.

Setting up a `Configuration` can be more work, depending on the OAuth service you're interacting with.

```swift
// backing storage for your authentication data. Without this, tokens will be tied to the lifetime of the `Authenticator`.
let storage = LoginStorage {
    // get login here
} storeLogin: { login in
    // store `login` for later retrieval
}

// application credentials for your OAuth service
let appCreds = AppCredentials(
    clientId: "client_id",
    clientPassword: "client_secret",
    scopes: [],
    callbackURL: URL(string: "my://callback")!
)

// the user authentication function
let userAuthenticator = ASWebAuthenticationSession.userAuthenticator

// functions that define how tokens are issued and refreshed
// This is the most complex bit, as all the pieces depend on exactly how the OAuth-based service works.
// parConfiguration, and dpopJWTGenerator are optional
let tokenHandling = TokenHandling(
    parConfiguration: PARConfiguration(url: parEndpointURL, parameters: extraQueryParams),
    authorizationURLProvider: { params in URL(string: "based on app credentials") }
    loginProvider: { params in ... }
    refreshProvider: { existingLogin, appCreds, urlLoader in ... },
    responseStatusProvider: TokenHandling.refreshOrAuthorizeWhenUnauthorized,
    dpopJWTGenerator: { params in "signed JWT" },
    pkce: PKCEVerifier(hash: "S256", hasher: { ... })
)

let config = Authenticator.Configuration(
    appCredentials: appCreds,
    loginStorage: storage,
    tokenHandling: tokenHandling,
    userAuthenticator: userAuthenticator
)

let authenticator = Authenticator(config: config)

let myRequest = URLRequest(...)

let (data, response) = try await authenticator.response(for: myRequest)
```

If you want to receive the result of the authentication process without issuing a request first, you can specify
an optional `Authenticator.AuthenticationStatusHandler` callback function within the `Authenticator.Configuration` initializer.

This allows you to support special cases where you need to capture the `Login` object before executing your first
authenticated `URLRequest` and manage that separately.

``` swift
let authenticationStatusHandler: Authenticator.AuthenticationStatusHandler = { result in
    switch result {
    case .success (let login): 
        authenticatedLogin = login
    case .failure(let error):
        print("Authentication failed: \(error)")
    }
}

// Configure Authenticator with result callback
let config = Authenticator.Configuration(
    appCredentials: appCreds,
    tokenHandling: tokenHandling,
    mode: .manualOnly,
    userAuthenticator: userAuthenticator,
    authenticationStatusHandler: authenticationStatusHandler
)

let auth = Authenticator(config: config, urlLoader: mockLoader)
try await auth.authenticate()
if let authenticatedLogin = authenticatedLogin {
    // Process special case
    ...
}
```

### DPoP

Constructing and signing the JSON Web Token / JSON Web Keys necessary for DPoP suppot is mostly out of the scope of this library. But here's an example of how to do it, using [Jot](https://github.com/mattmassicotte/Jot), a really basic JWT/JWK library I put together. You should be able to use this as a guide if you want to use a different JWT/JWK library.

```swift
import Jot
import OAuthenticator

// generate a DPoP key
let key = DPoPKey.P256()

// define your claims, making sure to pay attention to the JSON coding keys
struct DPoPTokenClaims : JSONWebTokenPayload {
    // standard claims
    let iss: String?
    let jti: String?
    let iat: Date?
    let exp: Date?

    // custom claims, which could vary depending on the service you are working with
    let htm: String?
    let htu: String?
}

// produce a DPoPSigner.JWTGenerator function from that key
extension DPoPSigner {
    static func JSONWebTokenGenerator(dpopKey: DPoPKey) -> DPoPSigner.JWTGenerator {
        let id = dpopKey.id.uuidString
        
        return { params in
            // construct the private key
            let key = try dpopKey.p256PrivateKey
            
            // make the JWK
            let jwk = JSONWebKey(p256Key: key.publicKey)

            // fill in all the JWT fields, including whatever custom claims you need
            let newToken = JSONWebToken<DPoPTokenClaims>(
                header: JSONWebTokenHeader(
                    algorithm: .ES256,
                    type: params.keyType,
                    keyId: id,
                    jwk: jwk
                ),
                payload: DPoPTokenClaims(
                    iss: params.issuingServer,
                    htm: params.httpMethod,
                    htu: params.requestEndpoint
                )
            )
            
            return try newToken.encode(with: key)
        }
    }
}
```

### GitHub

OAuthenticator also comes with pre-packaged configuration for GitHub, which makes set up much more straight-forward.

```swift
// pre-configured for GitHub
let appCreds = AppCredentials(clientId: "client_id",
                              clientPassword: "client_secret",
                              scopes: [],
                              callbackURL: URL(string: "my://callback")!)

let config = Authenticator.Configuration(appCredentials: appCreds,
                                         tokenHandling: GitHub.tokenHandling())

let authenticator = Authenticator(config: config)

let myRequest = URLRequest(...)

let (data, response) = try await authenticator.response(for: myRequest)
```


### Mastodon

OAuthenticator also comes with pre-packaged configuration for Mastodon, which makes set up much more straight-forward.
For more info, please check out [https://docs.joinmastodon.org/client/token/](https://docs.joinmastodon.org/client/token/)

```swift
// pre-configured for Mastodon
let userTokenParameters = Mastodon.UserTokenParameters(
    host: "mastodon.social",
    clientName: "MyMastodonApp",
    redirectURI: "myMastodonApp://mastodon/oauth",
    scopes: ["read", "write", "follow"]
)

// The first thing we will need to do is to register an application, in order to be able to generate access tokens later.
// These values will be used to generate access tokens, so they should be cached for later use
let registrationData = try await Mastodon.register(with: userTokenParameters) { request in
    try await URLSession.shared.data(for: request)
}

// Now that we have an application, let’s obtain an access token that will authenticate our requests as that client application.
guard let redirectURI = registrationData.redirectURI, let callbackURL = URL(string: redirectURI) else {
    throw AuthenticatorError.missingRedirectURI
}

let appCreds = AppCredentials(
    clientId: registrationData.clientID,
    clientPassword: registrationData.clientSecret,
    scopes: userTokenParameters.scopes,
    callbackURL: callbackURL
)

let config = Authenticator.Configuration(
    appCredentials: appCreds,
    tokenHandling: Mastodon.tokenHandling(with: userTokenParameters)
)

let authenticator = Authenticator(config: config)

var urlBuilder = URLComponents()
urlBuilder.scheme = Mastodon.scheme
urlBuilder.host = userTokenParameters.host

guard let url = urlBuilder.url else {
    throw AuthenticatorError.missingScheme
}

let request = URLRequest(url: url)

let (data, response) = try await authenticator.response(for: request)
```

### Google API
OAuthenticator also comes with pre-packaged configuration for Google APIs (access to Google Drive, Google People, Google Calendar, ...) according to the application requested scopes.

More info about those at [Google Workspace](https://developers.google.com/workspace). The Google OAuth process is described in [Google Identity](https://developers.google.com/identity) 

Integration example below: 
```swift
// Configuration for Google API

// Define how to store and retrieve the Google Access and Refresh Token
let storage = LoginStorage {
    // Fetch token and return them as a Login object
    return LoginFromSecureStorage(...) 
} storeLogin: { login in
    // Store access and refresh token in Secure storage
    MySecureStorage(login: login)
}

let appCreds = AppCredentials(clientId: googleClientApp.client_id,
                              clientPassword: googleClientApp.client_secret,
                              scopes: googleClientApp.scopes,
                              callbackURL: googleClient.callbackURL)

let config = Authenticator.Configuration(appCredentials: Self.oceanCredentials,
                                         loginStorage: storage,
                                         tokenHandling: tokenHandling,
                                         mode: .automatic)

let authenticator = Authenticator(config: config)

// If you just want the user to authenticate his account and get the tokens, do 1:
// If you want to access a secure Google endpoint with the proper access token, do 2:

// 1: Only Authenticate
try await authenticator.authenticate()

// 2: Access secure Google endpoint (ie: Google Drive: upload a file) with access token
var urlBuilder = URLComponents()
urlBuilder.scheme = GoogleAPI.scheme          // https:
urlBuilder.host = GoogleAPI.host              // www.googleapis.com
urlBuilder.path = GoogleAPI.path              // /upload/drive/v3/files
urlBuilder.queryItems = [
    URLQueryItem(name: GoogleDrive.uploadType, value: "media"),
]

guard let url = urlBuilder.url else {
    throw AuthenticatorError.missingScheme
}

let request = URLRequest(url: url)
request.httpMethod = "POST"
request.httpBody = ...          // File data to upload

let (data, response) = try await authenticator.response(for: request)
```

### Bluesky API

Bluesky has a [complex](https://docs.bsky.app/docs/advanced-guides/oauth-client) OAuth implementation.

> [!WARNING]
> bsky.social's DPoP nonce changes frequently (maybe every 10-30 seconds?). I have observed that if the nonce changes between when a user requested a 2FA code and the code being entered, the server will reject the login attempt. Trying again will involve user interaction.

Resovling PDS servers for a user is involved and beyond the scope of this library. However, [ATResolve](https://github.com/mattmassicotte/ATResolve) might help!

If you are using a platform that does not have [CryptoKit](https://developer.apple.com/documentation/cryptokit/) available, like Linux, you'll have to supply a `PKCEVerifier` parameter to the `Bluesky.tokenHandling` function.

See above for an example of how to implement DPoP JWTs.

```swift
let responseProvider = URLSession.defaultProvider
let account = "myhandle.com"
let server = "https://bsky.social"
let clientMetadataEndpoint = "https://example.com/public/facing/client-metadata.json"

// You should know the client configuration, and could generate the needed AppCredentials struct manually instead.
// The required fields are "clientId", "callbackURL", and "scopes"
let clientConfig = try await ClientMetadata.load(for: clientMetadataEndpoint, provider: provider)
let serverConfig = try await ServerMetadata.load(for: server, provider: provider)

let jwtGenerator: DPoPSigner.JWTGenerator = { params in
    // generate a P-256 signed token that uses `params` to match the specifications from
    // https://docs.bsky.app/docs/advanced-guides/oauth-client#dpop
}

let tokenHandling = Bluesky.tokenHandling(
    account: account,
    server: serverConfig,
    client: clientConfig,
    jwtGenerator: jwtGenerator
)

let config = Authenticator.Configuration(
    appCredentials: clientConfig.credentials,
    loginStorage: loginStore,
    tokenHandling: tokenHandling
)

let authenticator = Authenticator(config: config)

// you can now use this authenticator to make requests against the user's PDS. Remember, the PDS will not be the same as the authentication server.
```

## Contributing and Collaboration

I'd love to hear from you! Get in touch via an issue or pull request.

I prefer collaboration, and would love to find ways to work together if you have a similar project.

I prefer indentation with tabs for improved accessibility. But, I'd rather you use the system you want and make a PR than hesitate because of whitespace.

By participating in this project you agree to abide by the [Contributor Code of Conduct](CODE_OF_CONDUCT.md).

[build status]: https://github.com/ChimeHQ/OAuthenticator/actions
[build status badge]: https://github.com/ChimeHQ/OAuthenticator/workflows/CI/badge.svg
[platforms]: https://swiftpackageindex.com/ChimeHQ/OAuthenticator
[platforms badge]: https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FChimeHQ%2FOAuthenticator%2Fbadge%3Ftype%3Dplatforms
[documentation]: https://swiftpackageindex.com/ChimeHQ/OAuthenticator/main/documentation
[documentation badge]: https://img.shields.io/badge/Documentation-DocC-blue
