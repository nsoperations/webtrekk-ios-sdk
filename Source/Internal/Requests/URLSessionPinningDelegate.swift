//
//  URLSessionPinningDelegate.swift
//  Webtrekk
//
//  Created by Martin Demiddel on 14.08.18.
//  Copyright © 2018 Webtrekk. All rights reserved.
//

import Foundation
import Security

// because of usage of Security, which is only available > 10.3 we need to check
@available(watchOSApplicationExtension 3.3, tvOS 10.3, iOS 10.3, *)
class URLSessionPinningDelegate: NSObject, URLSessionDelegate {
    let pinnedPublicKeyHash: String = WebtrekkTracking.getPinning()
    let rsa2048Asn1Header: [UInt8] = [
        0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
    ]

    private func sha256(data: Data) -> String {
        return String(bytes: rsa2048Asn1Header.sha256(), encoding: .utf8)!
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
        ) {

        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            if let serverTrust = challenge.protectionSpace.serverTrust {
                var secresult = SecTrustResultType.invalid
                let status = SecTrustEvaluate(serverTrust, &secresult)

                if errSecSuccess == status {
                    print(SecTrustGetCertificateCount(serverTrust))

                    if let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {

                        // Public key pinning
                        let serverPublicKey = SecCertificateCopyPublicKey(serverCertificate)
                        let serverPublicKeyData: NSData = SecKeyCopyExternalRepresentation(serverPublicKey!, nil )!
                        let keyHash = sha256(data: serverPublicKeyData as Data)

                        // TODO: create a loop & Set of all pins from WebtrekkTracking (currently only 1)
                        if keyHash == pinnedPublicKeyHash {
                            // Success! This is our server
                            completionHandler(.useCredential, URLCredential(trust: serverTrust))

                            return
                        }
                    }
                }
            }
        }

        // Pinning failed
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
