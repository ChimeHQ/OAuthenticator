[![Build Status][build status badge]][build status]
[![License][license badge]][license]

# OAuthenticator
Lightweight OAuth 2.0 request authentication in Swift

There are lots of OAuth solutions out there. This one is small, uses Swift concurrency, and offers fine-grained control over the process. It also comes with optional integration with `ASWebAuthenticationSession`.

## Usage

The main type is the `Authenticator`. It can execute a `URLRequest` in a similar fashion to `URLSession`, but will handle all authentication requirements and tack on the needed `Authorization` header. It's behavior is controlled via its `Authenticator.Configuration` and `URLResponseProvider`. By default, the `URLResponseProvider` will be a private `URLSession`, but you can fully customize this if needed.

Setting up a `Configuration` can be more work, depending on how the OAuth service you'll be interacting with will work.

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
let userAuthenticator = ASWebAuthenticationSession.webAuthenticator

// functions that define how tokens are issued and refreshed
// This is the most complex bit, as all the pieces depend on exactly how the OAuth-based service works
let tokenHandling = TokenHandling(authorizationURLProvider: { appCreds in URL(string: "based on app credentials") }
                                  loginProvider: { authURL, appCreds, codeURL, urlLoader in ... }
                                  refreshProvider: { existingLogin, appCreds, urlLoader in ... })

let config = Authenticator.Configuration(appCredentials: appCreds,
                                         loginStorage: storage,
                                         tokenHandling: <#T##TokenHandling#>,
                                         userAuthenticator: userAuthenticator)

let authenticator = Authenticator(config: config)

let myRequest = URLRequest(...)

let (data, response) = try await authenticator.response(for: myRequest)
```

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

If you'd like to contribute a similar thing for another popular service, please open a PR!

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
