extension AsyncSequence {
	func collect() async throws -> [Element] {
		try await reduce(into: [Element]()) { $0.append($1) }
	}
}

extension AsyncStream.Continuation where Element == String {
	func checkpoint() {
		yield("checkpoint")
	}
}

extension AsyncStream where Element == String {
	func collect(finishing continuation: Self.Continuation) async throws -> [Element] {
		continuation.finish()

		return try await collect()
	}

	func collectToCheckpoint() async throws -> [Element] {
		var elements: [Element] = []

		for try await element in self {
			elements.append(element)

			if element == "checkpoint" {
				break
			}
		}

		return elements
	}
}
