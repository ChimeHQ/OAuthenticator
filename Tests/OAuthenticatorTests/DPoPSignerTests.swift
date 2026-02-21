import Foundation
import OAuthenticator
import Testing

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

enum RequestError: Error, Equatable {
	case tooManyRequests
}

final class MockResponseProvider: @unchecked Sendable {

	var responses: [Result<(Data, HTTPURLResponse), Error>] = []
	private(set) var requests: [URLRequest] = []
	private let lock = NSLock()

	init() {}

	func response(for request: URLRequest) throws -> (Data, HTTPURLResponse) {
		try lock.withLock {
			requests.append(request)

			if requests.count > responses.count {
				throw RequestError.tooManyRequests
			}

			return try responses[requests.count - 1].get()
		}
	}

	var allRequested: Bool {
		return requests.count == responses.count
	}

	var notAllRequested: Bool {
		return requests.count < responses.count
	}

	var responseProvider: URLResponseProvider {
		return { try self.response(for: $0) }
	}
}

typealias Assertions =
	@Sendable (
		_ request: Int,
		_ parameters: DPoPSigner.JWTParameters,
		_ loader: MockResponseProvider?
	) throws -> Void

func genericJWTGenerator() -> DPoPSigner.JWTGenerator {
	return { _ in "my_fake_jwt" }
}

func assertingJWTGenerator(loader: MockResponseProvider?, assertions: Assertions?)
	-> DPoPSigner.JWTGenerator
{
	return { parameters in
		var req = 0
		if let requests = loader?.requests {
			req = requests.count
		}
		debugPrint("Request:", req, "Params:", parameters)

		if let assertions = assertions {
			try assertions(req, parameters, loader)
		}

		return "my_fake_jwt"
	}
}

func RequestFor(url: String, method: String = "GET") -> URLRequest {
	var request = URLRequest(url: URL(string: url)!)
	request.httpMethod = method
	return request
}

struct JWTAssertion {
	let htu: String
	let htm: String
}

struct DPoPSignerTests {
	@MainActor
	@Test func basicSignature() async throws {
		let signer = DPoPSigner()

		var request = RequestFor(url: "https://resource.example/test")
		let assertTokenParams = assertingJWTGenerator(
			loader: nil,
			assertions: {
				(request: Int, parameters: DPoPSigner.JWTParameters, loader: MockResponseProvider?) in

				#expect(parameters.httpMethod == "GET")
				#expect(parameters.requestEndpoint == "https://resource.example/test")
				#expect(parameters.nonce == "test_nonce")
				#expect(parameters.tokenHash == "token_hash")
			})

		try await signer.buildProof(
			&request,
			isolation: MainActor.shared,
			using: assertTokenParams,
			nonce: "test_nonce",
			token: "token",
			tokenHash: "token_hash"
		)

		#expect(request.value(forHTTPHeaderField: "Authorization") == "DPoP token")
		#expect(request.value(forHTTPHeaderField: "DPoP") == "my_fake_jwt")
	}

	@MainActor
	@Test func missingTokenHashThrows() async throws {
		let signer = DPoPSigner()
		var request = RequestFor(url: "https://resource.example/test")

		await #expect(throws: DPoPError.requestInvalid(request)) {
			try await signer.buildProof(
				&request,
				isolation: MainActor.shared,
				using: genericJWTGenerator(),
				nonce: "test_nonce",
				token: "token",
				tokenHash: nil
			)
		}
	}

	@MainActor
	@Test func withoutParameters() async throws {
		let signer = DPoPSigner()

		var request = RequestFor(url: "https://resource.example/test")
		let assertTokenParams = assertingJWTGenerator(
			loader: nil,
			assertions: {
				(request: Int, parameters: DPoPSigner.JWTParameters, loader: MockResponseProvider?) in

				#expect(parameters.httpMethod == "GET")
				#expect(parameters.requestEndpoint == "https://resource.example/test")
				#expect(parameters.nonce == nil)
				#expect(parameters.tokenHash == nil)
			})

		try await signer.buildProof(
			&request,
			isolation: MainActor.shared,
			using: assertTokenParams,
			nonce: nil,
			token: nil,
			tokenHash: nil
		)

		#expect(request.value(forHTTPHeaderField: "Authorization") == nil)
		#expect(request.value(forHTTPHeaderField: "DPoP") == "my_fake_jwt")
	}

	@MainActor
	@Test(
		"Correctly constructs the JWTParameters",
		arguments: zip(
			[
				RequestFor(url: "https://example.com/foo/bar/baz.json"),
				RequestFor(url: "https://example.com/foo.json?query=param"),
				RequestFor(url: "https://example.com/foo.json#fragment"),
				RequestFor(url: "https://example.com/foo.json?foo=bar#fragment"),
				RequestFor(url: "https://example.com/foo?query=param", method: "POST"),
			],
			[
				JWTAssertion(htu: "https://example.com/foo/bar/baz.json", htm: "GET"),
				JWTAssertion(htu: "https://example.com/foo.json", htm: "GET"),
				JWTAssertion(htu: "https://example.com/foo.json", htm: "GET"),
				JWTAssertion(htu: "https://example.com/foo.json", htm: "GET"),
				JWTAssertion(htu: "https://example.com/foo", htm: "POST"),
			]))
	func handlesParameters(inputRequest: URLRequest, expectedParams: JWTAssertion) async throws {
		var request = inputRequest
		let signer = DPoPSigner()

		let assertTokenParams = assertingJWTGenerator(
			loader: nil,
			assertions: {
				(request: Int, parameters: DPoPSigner.JWTParameters, loader: MockResponseProvider?) in

				debugPrint(parameters, expectedParams)

				#expect(parameters.httpMethod == expectedParams.htm)
				#expect(parameters.requestEndpoint == expectedParams.htu)
			})

		try await signer.buildProof(
			&request,
			isolation: MainActor.shared,
			using: assertTokenParams,
			nonce: "test_nonce",
			token: "token",
			tokenHash: "token_hash"
		)

		#expect(request.value(forHTTPHeaderField: "Authorization") != nil)
		#expect(request.value(forHTTPHeaderField: "DPoP") != nil)
	}

	@MainActor
	@Test func overwritesAuthorization() async throws {
		// We expect the original request to not be modified:
		let signer = DPoPSigner()
		let authorization = "Bearer foo"

		var request = URLRequest(url: URL(string: "https://example.com")!)
		request.setValue(authorization, forHTTPHeaderField: "Authorization")

		try await signer.buildProof(
			&request,
			isolation: MainActor.shared,
			using: genericJWTGenerator(),
			nonce: "test_nonce",
			token: "token",
			tokenHash: "token_hash"
		)

		#expect(request.value(forHTTPHeaderField: "Authorization") == "DPoP token")
		#expect(request.value(forHTTPHeaderField: "DPoP") == "my_fake_jwt")
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
				isolation: MainActor.shared,
				using: genericJWTGenerator(),
				nonce: "test_nonce",
				token: "token",
				tokenHash: "token_hash"
			)
		}

		#expect(request.value(forHTTPHeaderField: "Authorization") == authorization)
		#expect(request.value(forHTTPHeaderField: "DPoP") == nil)
	}
}

struct DPoPSignerRequestTests {
	@MainActor
	@Test func authorizationResponseSuccess() async throws {
		let signer = DPoPSigner()

		let requestedURL = URL(string: "https://as.example/oauth/token")!
		let request = URLRequest(url: requestedURL)

		let mockLoader = MockResponseProvider()
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
			using: assertingJWTGenerator(loader: mockLoader, assertions: nil),
			token: "test-token",
			tokenHash: "test-abc123",
			isAuthServer: true,
			responseProvider: mockLoader.responseProvider
		)

		#expect(mockLoader.allRequested)

		let nonce = try #require(
			signer.testRetrieveNonceForOrigin(url: URL(string: "https://as.example")!)
		)
		#expect(nonce.nonce == "test-nonce")

		#expect(resultResponse.statusCode == 200)
		#expect(resultData == Data(payload.utf8))
	}

	@MainActor
	@Test func resourceResponseWWWAuthInvalidRequest() async throws {
		let signer = DPoPSigner()

		// We are testing that we can make a request against a Resource Server,
		// which returns a WWW-Authenticate error due to invalid it being an invalid
		// request (i.e., not DPoP), upon that error, we don't retry the request.
		let requestedURL = URL(string: "https://resource.example.com/")!
		let request = URLRequest(url: requestedURL)

		let mockLoader = MockResponseProvider()
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
			using: assertingJWTGenerator(
				loader: mockLoader,
				assertions: {
					(request: Int, parameters: DPoPSigner.JWTParameters, loader: MockResponseProvider?) in
					#expect(request == 0)
					#expect(parameters.nonce == nil)
				}),
			token: "test-token",
			tokenHash: "test-abc123",
			isAuthServer: false,
			responseProvider: mockLoader.responseProvider
		)

		// We don't expect the request to be
		#expect(mockLoader.notAllRequested)
		#expect(mockLoader.requests.count == 1)

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
		let requestedURL = URL(string: "https://resource.example.com/")!
		let request = URLRequest(url: requestedURL)

		let mockLoader = MockResponseProvider()
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
			using: assertingJWTGenerator(
				loader: mockLoader,
				assertions: {
					(request: Int, parameters: DPoPSigner.JWTParameters, loader: MockResponseProvider?) in
					if request == 0 {
						#expect(parameters.nonce == nil)
					} else if request == 1 {
						#expect(parameters.nonce == "test-nonce-1")
					}
				}),
			token: "test-token",
			tokenHash: "test-abc123",
			isAuthServer: false,
			responseProvider: mockLoader.responseProvider
		)

		#expect(mockLoader.allRequested)

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
		let requestedURL = URL(string: "https://as.example/oauth/token")!
		let request = URLRequest(url: requestedURL)

		let mockLoader = MockResponseProvider()
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
			using: assertingJWTGenerator(
				loader: mockLoader,
				assertions: {
					(request: Int, parameters: DPoPSigner.JWTParameters, loader: MockResponseProvider?) in
					if request == 0 {
						#expect(parameters.nonce == nil)
					} else if request == 1 {
						#expect(parameters.nonce == "test-nonce-1")
					}
				}),
			token: "test-token",
			tokenHash: "test-abc123",
			isAuthServer: nil,  // this allows either AS or RS logic to apply
			responseProvider: mockLoader.responseProvider
		)

		#expect(mockLoader.allRequested)

		let nonce = try #require(
			signer.testRetrieveNonceForOrigin(url: URL(string: "https://as.example")!)
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
		let requestedURL = URL(string: "https://as.example/oauth/token")!
		let request = URLRequest(url: requestedURL)

		let mockLoader = MockResponseProvider()
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
			using: genericJWTGenerator(),
			token: "test-token",
			tokenHash: "test-abc123",
			isAuthServer: true,
			responseProvider: mockLoader.responseProvider
		)

		#expect(mockLoader.notAllRequested)
		#expect(mockLoader.requests.count == 1)

		let nonce = try #require(
			signer.testRetrieveNonceForOrigin(url: URL(string: "https://as.example")!)
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
		let asRequestUrl = URL(string: "https://as.example/oauth/token")!
		let asRequest = URLRequest(url: asRequestUrl)

		let rsRequestUrl = URL(string: "https://resource.example/")!
		let rsRequest = URLRequest(url: rsRequestUrl)

		let mockLoader = MockResponseProvider()
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

		let tokenGenerator = assertingJWTGenerator(
			loader: mockLoader,
			assertions: {
				(request: Int, parameters: DPoPSigner.JWTParameters, loader: MockResponseProvider?) in
				if request == 0 {
					#expect(parameters.nonce == nil)
					#expect(parameters.requestEndpoint == "https://as.example/oauth/token")
				} else if request == 1 {
					#expect(parameters.nonce == "test-as-nonce-1")
					#expect(parameters.requestEndpoint == "https://as.example/oauth/token")
				} else if request == 2 {
					// We don't have a DPoP Nonce for the resource server, because it's a new origin:
					#expect(parameters.nonce == nil)
					#expect(parameters.requestEndpoint == "https://resource.example/")
				}
			})

		let asResult = try await signer.response(
			isolation: MainActor.shared,
			for: asRequest,
			using: tokenGenerator,
			token: "test-token",
			tokenHash: "test-abc123",
			isAuthServer: true,
			responseProvider: mockLoader.responseProvider
		)

		// We retry due to nonce failure:
		#expect(mockLoader.requests.count == 2)

		#expect(asResult.1.statusCode == 200)
		#expect(asResult.0 == Data("authorization server".utf8))

		let rsResult = try await signer.response(
			isolation: MainActor.shared,
			for: rsRequest,
			using: tokenGenerator,
			token: "test-token",
			tokenHash: "test-abc123",
			isAuthServer: false,
			responseProvider: mockLoader.responseProvider
		)

		#expect(rsResult.1.statusCode == 200)
		#expect(rsResult.0.elementsEqual("resource server".utf8))

		// We now have the resource server request completed, so all requests are completed:
		#expect(mockLoader.allRequested)

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
