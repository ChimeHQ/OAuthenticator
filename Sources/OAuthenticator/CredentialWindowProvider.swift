#if os(iOS)
import UIKit
#else
import Cocoa
#endif
import AuthenticationServices

public class CredentialWindowProvider: NSObject {
}

extension CredentialWindowProvider: ASWebAuthenticationPresentationContextProviding {
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        #if os(iOS)
        #else
        return NSApp.keyWindow ?? NSApp.mainWindow ?? NSApp.orderedWindows.first!
        #endif
    }
}
