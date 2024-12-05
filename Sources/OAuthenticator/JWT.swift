import Foundation

enum JSONWebTokenError: Error {
	case signatureInvalid
}

enum JSONWebTokenAlgorithm: String, Codable, Hashable, Sendable {
	case ES256
}

protocol JSONWebTokenHeader: Codable {
	var algorithm: JSONWebTokenAlgorithm { get }
}

typealias JSONWebTokenSigner = (JSONWebTokenAlgorithm, Data) throws -> Data

struct JSONWebToken<Header: JSONWebTokenHeader, Payload: Codable> {
	public let header: Header
	public let payload: Payload
	
	public init(header: Header, payload: Payload) {
		self.header = header
		self.payload = payload
	}
	
	public func encode(with signer: JSONWebTokenSigner) throws -> String {
		let encoder = JSONEncoder()
		
		encoder.outputFormatting = .sortedKeys
		
		let headerString = try encoder.encode(header).base64EncodedURLEncodedString()
		let payloadString = try encoder.encode(payload).base64EncodedURLEncodedString()
		
		let inputData = [headerString, payloadString].joined(separator: ".")
		let signatureData = try signer(header.algorithm, Data(inputData.utf8))

		let signature = signatureData.base64EncodedURLEncodedString()
		
		return [headerString, payloadString, signature].joined(separator: ".")
	}
}

extension JSONWebToken: Equatable where Header: Equatable, Payload: Equatable {}
extension JSONWebToken: Hashable where Header: Hashable, Payload: Hashable {}
extension JSONWebToken: Sendable where Header: Sendable, Payload: Sendable {}

#if canImport(CryptoKit)
import CryptoKit

extension JSONWebToken {
	public init(encodedString: String, validator: (JSONWebTokenAlgorithm, Data, Data) throws -> Bool) throws {
		let components = encodedString.components(separatedBy: ".")
		let headerData = Data(base64URLEncoded: components[0])!
		let payloadData = Data(base64URLEncoded: components[1])!
		let signatureData = Data(base64URLEncoded: components[2])!
		
		let decoder = JSONDecoder()
		
		self.header = try decoder.decode(Header.self, from: headerData)
		self.payload = try decoder.decode(Payload.self, from: payloadData)
		
		let message = Data(components.dropLast().joined(separator: ".").utf8)
		
		guard try validator(self.header.algorithm, message, signatureData) else {
			throw JSONWebTokenError.signatureInvalid
		}
	}
}
#endif
