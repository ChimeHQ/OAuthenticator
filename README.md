[![Build Status][build status badge]][build status]
[![License][license badge]][license]
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

There's also built-in support for services to streamline integration:

- GitHub
- Mastodon

If you'd like to contribute a similar thing for another service, please open a PR!

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
let appCreds = AppCredentials(clientId: "client_id",
                              clientPassword: "client_secret",
                              scopes: [],
                              callbackURL: URL(string: "my://callback")!)

// the user authentication function
let userAuthenticator = ASWebAuthenticationSession.userAuthenticator

// functions that define how tokens are issued and refreshed
// This is the most complex bit, as all the pieces depend on exactly how the OAuth-based service works
let tokenHandling = TokenHandling(authorizationURLProvider: { appCreds in URL(string: "based on app credentials") }
                                  loginProvider: { authURL, appCreds, codeURL, urlLoader in ... }
                                  refreshProvider: { existingLogin, appCreds, urlLoader in ... },
                                  responseStatusProvider: TokenHandling.refreshOrAuthorizeWhenUnauthorized)

let config = Authenticator.Configuration(appCredentials: appCreds,
                                         loginStorage: storage,
                                         tokenHandling: tokenHandling,
                                         userAuthenticator: userAuthenticator)

let authenticator = Authenticator(config: config)

let myRequest = URLRequest(...)

let (data, response) = try await authenticator.response(for: myRequest)
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
    scopes: ["read", "write", "follow"])

// The first thing we will need to do is to register an application, in order to be able to generate access tokens later.
// These values will be used to generate access tokens, so they should be cached for later use
let registrationData = try await Mastodon.register(with: userTokenParameters) { request in
    try await URLSession.shared.data(for: request)
}

// Now that we have an application, let’s obtain an access token that will authenticate our requests as that client application.
guard let redirectURI = registrationData.redirect_uri, let callbackURL = URL(string: redirectURI) else {
    throw AuthenticatorError.missingRedirectURI
}

let appCreds = AppCredentials(clientId: registrationData.client_id,
                              clientPassword: registrationData.client_secret,
                              scopes: userTokenParameters.scopes,
                              callbackURL: callbackURL)

let config = Authenticator.Configuration(appCredentials: appCreds,
                                         tokenHandling: Mastodon.tokenHandling(with: userTokenParameters))

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

## Contributing and Collaboration

I prefer collaboration, and would love to find ways to work together if you have a similar project.

I prefer indentation with tabs for improved accessibility. But, I'd rather you use the system you want and make a PR than hesitate because of whitespace.

## Suggestions and Feedback

I'd love to hear from you! Get in touch via [mastodon](https://mastodon.social/@mattiem), an issue, or a pull request.

By participating in this project you agree to abide by the [Contributor Code of Conduct](CODE_OF_CONDUCT.md).

[build status]: https://github.com/ChimeHQ/OAuthenticator/actions
[build status badge]: https://github.com/ChimeHQ/OAuthenticator/workflows/CI/badge.svg
[license]: https://opensource.org/licenses/BSD-3-Clause
[license badge]: https://img.shields.io/github/license/ChimeHQ/OAuthenticator
[platforms]: https://swiftpackageindex.com/ChimeHQ/OAuthenticator
[platforms badge]: https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2FChimeHQ%2FOAuthenticator%2Fbadge%3Ftype%3Dplatforms
[documentation]: https://swiftpackageindex.com/ChimeHQ/OAuthenticator/main/documentation
[documentation badge]: https://img.shields.io/badge/Documentation-DocC-blue
