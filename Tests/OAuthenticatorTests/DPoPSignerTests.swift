import Foundation
import OAuthenticator
import Testing

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

struct ExamplePayload: Codable, Hashable, Sendable {
	let value: String
}

struct DPoPSignerTests {
	@MainActor
	@Test func basicSignature() async throws {
		let signer = DPoPSigner()

		var request = URLRequest(url: URL(string: "https://example.com")!)

		try await signer.buildProof(
			&request,
			nonce: "test_nonce",
			isolation: MainActor.shared,
			using: { _ in "my_fake_jwt" },
			token: "token",
			tokenHash: "token_hash"
		)

		let headers = try #require(request.allHTTPHeaderFields)

		#expect(headers["Authorization"] == "DPoP token")
		#if !os(Linux)
			// I'm unsure why exactly this test is failing on Linux only, but I suspect it is due to
			// platform differences in FoundationNetworking.
			#expect(headers["DPoP"] == "my_fake_jwt")
		#endif
	}

	@MainActor
	@Test func invalidRequest() async throws {
		// We expect the original request to not be modified:
		let signer = DPoPSigner()
		let authorization = "Bearer foo"

		var request = URLRequest(url: URL(string: "https://example.com")!)
		request.setValue(authorization, forHTTPHeaderField: "Authorization")

		// Ensure the guard for url / method will throw:
		request.url = nil
		#expect(request.url == nil)

		await #expect(throws: DPoPError.requestInvalid(request)) {
			try await signer.buildProof(
				&request,
				nonce: "test_nonce",
				isolation: MainActor.shared,
				using: { _ in "my_fake_jwt" },
				token: "token",
				tokenHash: "token_hash"
			)
		}

		let headers = try #require(request.allHTTPHeaderFields)

		#expect(headers["Authorization"] == authorization)
		#expect(headers["DPoP"] == nil)
	}

	@MainActor
	@Test func authorizationResponseSuccess() async throws {
		let signer = DPoPSigner()

		let requestedURL = URL(string: "https://as.example/oauth/token")!
		let request = URLRequest(url: requestedURL)

		let mockLoader = MockURLResponseProvider()
		let payload = """
				{"access_token":"1", "sub":"2", "scope":"3", "token_type":"DPoP","expires_in":120}
			"""

		mockLoader.responses = [
			.success(
				(
					Data(payload.utf8),
					HTTPURLResponse(
						url: requestedURL, statusCode: 200, httpVersion: nil,
						headerFields: ["DPoP-Nonce": "test-nonce"])!
				))
		]

		let (resultData, resultResponse) = try await signer.response(
			isolation: MainActor.shared,
			for: request,
			using: { _ in "my_fake_jwt" },
			token: "test-token",
			tokenHash: "test-abc123",
			issuingServer: "https://as.example",
			responseProvider: mockLoader.responseProvider
		)

		#expect(mockLoader.requestCount() == 1)

		let nonce = try #require(
			signer.testRetrieveNonceForOrigin(url: URL(string: "https://as.example")!)
		)
		#expect(nonce.nonce == "test-nonce")

		#expect(resultResponse.statusCode == 200)
		#expect(resultData == Data(payload.utf8))
	}

	@MainActor
	@Test func resourceResponseWWWAuthFail() async throws {
		let signer = DPoPSigner()

		// We are testing that we can make a request against a Resource Server,
		// which returns a WWW-Authenticate error due to invalid it being an invalid
		// request (i.e., not DPoP), upon that error, we don't retry the request.
		let issuer = "https://as.example"
		let requestedURL = URL(string: "https://resource.example.com/")!
		let request = URLRequest(url: requestedURL)

		let mockLoader = MockURLResponseProvider()
		let failurePayload = "failed"

		mockLoader.responses = [
			.success(
				(
					Data(failurePayload.utf8),
					HTTPURLResponse(
						url: requestedURL, statusCode: 401, httpVersion: nil,
						headerFields: [
							"WWW-Authenticate": "DPoP error=\"invalid_request\"", "DPoP-Nonce": "test-nonce-1",
						])!
				)),
			.success(
				(
					Data(),
					HTTPURLResponse(
						url: requestedURL, statusCode: 200, httpVersion: nil,
						headerFields: [
							"DPoP-Nonce": "test-nonce-2"
						])!
				)),
		]

		let (resultData, resultResponse) = try await signer.response(
			isolation: MainActor.shared,
			for: request,
			using: { parameters in
				let req = mockLoader.requestCount()
				debugPrint(parameters, mockLoader.requestCount())

				if req == 0 {
					#expect(parameters.nonce == nil)
				} else if req == 1 {
					#expect(parameters.nonce == "test-nonce-1")
				}

				return "my_fake_jwt"
			},
			token: "test-token",
			tokenHash: "test-abc123",
			issuingServer: issuer,
			responseProvider: mockLoader.responseProvider
		)

		#expect(mockLoader.requestCount() == 1)

		let nonce = try #require(
			signer.testRetrieveNonceForOrigin(url: URL(string: "https://resource.example.com")!)
		)
		#expect(nonce.nonce == "test-nonce-1")

		#expect(resultResponse.statusCode == 401)
		#expect(resultData.elementsEqual(failurePayload.utf8))
	}

	@MainActor
	@Test func resourceResponseWWWAuthRetry() async throws {
		let signer = DPoPSigner()

		// We are testing that we can make a request against a Resource Server,
		// which returns a WWW-Authenticate error due to invalid DPoP Nonce,
		// upon that error, we retry the request with the given DPoP-Nonce header value.
		let issuer = "https://as.example"
		let requestedURL = URL(string: "https://resource.example.com/")!
		let request = URLRequest(url: requestedURL)

		let mockLoader = MockURLResponseProvider()
		let payload = """
				{"access_token":"1", "sub":"2", "scope":"3", "token_type":"DPoP","expires_in":120}
			"""

		mockLoader.responses = [
			.success(
				(
					Data("".utf8),
					HTTPURLResponse(
						url: requestedURL, statusCode: 401, httpVersion: nil,
						headerFields: [
							"WWW-Authenticate": "DPoP error=\"use_dpop_nonce\"", "DPoP-Nonce": "test-nonce-1",
						])!
				)),
			.success(
				(
					Data(payload.utf8),
					HTTPURLResponse(
						url: requestedURL, statusCode: 200, httpVersion: nil,
						headerFields: [
							"DPoP-Nonce": "test-nonce-2"
						])!
				)),
		]

		let (resultData, resultResponse) = try await signer.response(
			isolation: MainActor.shared,
			for: request,
			using: { parameters in
				let req = mockLoader.requestCount()
				debugPrint(parameters, mockLoader.requestCount())

				if req == 0 {
					#expect(parameters.nonce == nil)
				} else if req == 1 {
					#expect(parameters.nonce == "test-nonce-1")
				}
				return "my_fake_jwt"
			},
			token: "test-token",
			tokenHash: "test-abc123",
			issuingServer: issuer,
			responseProvider: mockLoader.responseProvider
		)

		#expect(mockLoader.requestCount() == 2)

		let nonce = try #require(
			signer.testRetrieveNonceForOrigin(url: URL(string: "https://resource.example.com")!)
		)
		#expect(nonce.nonce == "test-nonce-2")

		#expect(resultResponse.statusCode == 200)
		#expect(resultData.elementsEqual(payload.utf8))
	}

	@MainActor
	@Test func authorizationResponseAfterDPoPError() async throws {
		let signer = DPoPSigner()

		// We are making a request against an Authorization Server (the issuer),
		// which returns a DPoP Error Response body, with a DPoP-Nonce header. The
		// request is then retried with the supplied DPoP-Nonce header value, and
		// succeeds.
		let issuer = "https://as.example"
		let requestedURL = URL(string: "https://as.example/oauth/token")!
		let request = URLRequest(url: requestedURL)

		let mockLoader = MockURLResponseProvider()
		let nonceError = """
				{ "error": "use_dpop_nonce", "error_description": "Authorization server requires nonce in DPoP proof" }
			"""
		let payload = """
				{"access_token":"1", "sub":"2", "scope":"3", "token_type":"DPoP","expires_in":120}
			"""

		mockLoader.responses = [
			.success(
				(
					Data(nonceError.utf8),
					HTTPURLResponse(
						url: requestedURL, statusCode: 400, httpVersion: nil,
						headerFields: [
							"DPoP-Nonce": "test-nonce-1"
						])!
				)),
			.success(
				(
					Data(payload.utf8),
					HTTPURLResponse(
						url: requestedURL, statusCode: 200, httpVersion: nil,
						headerFields: ["DPoP-Nonce": "test-nonce-2"])!
				)),
		]

		let (resultData, resultResponse) = try await signer.response(
			isolation: MainActor.shared,
			for: request,
			using: { parameters in
				let req = mockLoader.requestCount()
				debugPrint(parameters, mockLoader.requestCount())

				if req == 0 {
					#expect(parameters.nonce == nil)
				} else if req == 1 {
					#expect(parameters.nonce == "test-nonce-1")
				}

				return "my_fake_jwt"
			},
			token: "test-token",
			tokenHash: "test-abc123",
			issuingServer: issuer,
			responseProvider: mockLoader.responseProvider
		)

		#expect(mockLoader.requestCount() == 2)

		let nonce = try #require(
			signer.testRetrieveNonceForOrigin(url: URL(string: issuer)!)
		)
		#expect(nonce.nonce == "test-nonce-2")

		#expect(resultResponse.statusCode == 200)
		#expect(resultData == Data(payload.utf8))
	}

	@MainActor
	@Test func authorizationResponseAfterInvalidRequestError() async throws {
		let signer = DPoPSigner()

		// We are making a request against an Authorization Server (the issuer),
		// which returns a DPoP Error Response body, with a DPoP-Nonce header. The
		// request is then retried with the supplied DPoP-Nonce header value, and
		// succeeds.
		let issuer = "https://as.example"
		let requestedURL = URL(string: "https://as.example/oauth/token")!
		let request = URLRequest(url: requestedURL)

		let mockLoader = MockURLResponseProvider()
		let oauthError = """
				{ "error": "invalid_request", "error_description": "This request was not valid" }
			"""

		mockLoader.responses = [
			.success(
				(
					Data(oauthError.utf8),
					HTTPURLResponse(
						url: requestedURL, statusCode: 400, httpVersion: nil,
						headerFields: [
							"DPoP-Nonce": "test-nonce-1"
						])!
				)),
			// We never actually get to this response:
			.success(
				(
					Data("never".utf8),
					HTTPURLResponse(
						url: requestedURL, statusCode: 200, httpVersion: nil,
						headerFields: ["DPoP-Nonce": "test-nonce-2"])!
				)),
		]

		let (resultData, resultResponse) = try await signer.response(
			isolation: MainActor.shared,
			for: request,
			using: { parameters in "my_fake_jwt" },
			token: "test-token",
			tokenHash: "test-abc123",
			issuingServer: issuer,
			responseProvider: mockLoader.responseProvider
		)

		#expect(mockLoader.requestCount() == 1)

		let nonce = try #require(
			signer.testRetrieveNonceForOrigin(url: URL(string: issuer)!)
		)
		#expect(nonce.nonce == "test-nonce-1")

		#expect(resultResponse.statusCode == 400)
		#expect(resultData == Data(oauthError.utf8))
	}

	@MainActor
	@Test func requestsAgainstDifferentOrigins() async throws {
		let signer = DPoPSigner()

		// We are making a request against an Authorization Server (the issuer),
		// which succeed with a DPoP-Nonce header. Then we request against a
		// resource server which succeeds.
		let issuer = "https://as.example/"
		let asRequestUrl = URL(string: "https://as.example/oauth/token")!
		let asRequest = URLRequest(url: asRequestUrl)

		let rsRequestUrl = URL(string: "https://resource.example/")!
		let rsRequest = URLRequest(url: rsRequestUrl)

		let mockLoader = MockURLResponseProvider()
		let nonceError = """
				{ "error": "use_dpop_nonce", "error_description": "Authorization server requires nonce in DPoP proof" }
			"""

		mockLoader.responses = [
			.success(
				(
					Data(nonceError.utf8),
					HTTPURLResponse(
						url: asRequestUrl, statusCode: 400, httpVersion: nil,
						headerFields: [
							"DPoP-Nonce": "test-as-nonce-1"
						])!
				)),
			.success(
				(
					Data("authorization server".utf8),
					HTTPURLResponse(
						url: asRequestUrl, statusCode: 200, httpVersion: nil,
						headerFields: [
							"DPoP-Nonce": "test-as-nonce-2"
						])!
				)),
			// We never actually get to this response:
			.success(
				(
					Data("resource server".utf8),
					HTTPURLResponse(
						url: rsRequestUrl, statusCode: 200, httpVersion: nil,
						headerFields: ["DPoP-Nonce": "test-rs-nonce-1"])!
				)),
		]

		let asResult = try await signer.response(
			isolation: MainActor.shared,
			for: asRequest,
			using: { parameters in
				debugPrint(parameters, mockLoader.requestCount())

				if mockLoader.requestCount() == 0 {
					#expect(parameters.nonce == nil)
					#expect(parameters.requestEndpoint == asRequestUrl.absoluteString)
				} else {
					#expect(parameters.nonce == "test-as-nonce-1")
					#expect(parameters.requestEndpoint == asRequestUrl.absoluteString)
				}

				return "my_fake_jwt"
			},
			token: "test-token",
			tokenHash: "test-abc123",
			issuingServer: issuer,
			responseProvider: mockLoader.responseProvider
		)

		// We retry due to nonce failure:
		#expect(mockLoader.requestCount() == 2)

		#expect(asResult.1.statusCode == 200)
		#expect(asResult.0 == Data("authorization server".utf8))

		let rsResult = try await signer.response(
			isolation: MainActor.shared,
			for: rsRequest,
			using: { parameters in
				debugPrint(parameters, mockLoader.requestCount())

				// We don't have a DPoP Nonce for the resource server, because it's a new origin:
				#expect(parameters.nonce == nil)
				#expect(parameters.requestEndpoint == rsRequestUrl.absoluteString)

				return "my_fake_jwt"
			},
			token: "test-token",
			tokenHash: "test-abc123",
			issuingServer: issuer,
			responseProvider: mockLoader.responseProvider
		)

		#expect(rsResult.1.statusCode == 200)
		#expect(rsResult.0.elementsEqual("resource server".utf8))

		// We now have the resource server request completed:
		#expect(mockLoader.requestCount() == 3)

		// Check the Authorization Server DPoP-Nonce didn't clobber the Resource
		// Server DPoP-Nonce:
		let asNonce = try #require(
			signer.testRetrieveNonceForOrigin(url: URL(string: "https://as.example")!)
		)
		#expect(asNonce.nonce == "test-as-nonce-2")

		let rsNonce = try #require(
			signer.testRetrieveNonceForOrigin(url: URL(string: "https://resource.example")!)
		)
		#expect(rsNonce.nonce == "test-rs-nonce-1")
	}
}
