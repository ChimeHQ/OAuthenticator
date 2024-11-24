struct JSONWebKey {
	public enum KeyType: String, Sendable {
		case rsa
		case ec
	}
	
	public let keyType: KeyType
}

final class DPoPSigner {
	
}
