#if os(iOS) || os(macOS)

#if os(iOS)
import UIKit
#else
import Cocoa
#endif
import AuthenticationServices

public final class CredentialWindowProvider: NSObject {
#if os(iOS)
	private var scenes: [UIWindowScene] {
		UIApplication.shared.connectedScenes.compactMap({ $0 as? UIWindowScene  })
	}

	private var window: UIWindow {
		if #available(iOS 15.0, *) {
			return scenes.compactMap({ $0.keyWindow }).first!
		} else {
			return scenes.flatMap({ $0.windows }).first!
		}
	}
#endif
}

extension CredentialWindowProvider: ASWebAuthenticationPresentationContextProviding {
	public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
#if os(iOS)
		return window
#else
		return NSApp.keyWindow ?? NSApp.mainWindow ?? NSApp.orderedWindows.first!
#endif
	}
}

#endif
