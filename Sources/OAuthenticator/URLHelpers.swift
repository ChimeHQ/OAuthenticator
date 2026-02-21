import Foundation

#if canImport(FoundationNetworking)
	import FoundationNetworking
#endif

// Only sets the port if the port is not the default port for http or https requests:
internal func omitWebDefaultPort(components: inout URLComponents, port: Int?, scheme: String) {
	guard let port = port else {
		return
	}

	if scheme == "http" || scheme == "https" {
		if scheme == "http" && port != 80 {
			components.port = port
		} else if scheme == "https" && port != 443 {
			components.port = port
		}
	} else {
		components.port = port
	}
}
