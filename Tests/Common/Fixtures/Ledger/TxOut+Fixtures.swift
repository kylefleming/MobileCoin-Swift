//
//  Copyright (c) 2020-2021 MobileCoin. All rights reserved.
//

// swiftlint:disable multiline_function_chains

@testable import MobileCoin
import XCTest

extension TxOut {
    enum Fixtures {}
}

extension TxOut.Fixtures {
    struct Default {
        let txOut: TxOut

        let serializedData = Self.serializedData
        let recipientAccountKey: AccountKey
        let keyImage: KeyImage
        let value = Self.value

        let wrongAccountKey: AccountKey

        init(accountIndex: UInt8 = 255) throws {
            let accountKey = Self.accountKey(accountIndex: accountIndex)
            try self.init(accountKey: accountKey)
        }

        init(accountKey: AccountKey) throws {
            self.recipientAccountKey = accountKey
            self.txOut = try Self.txOut(accountKey: recipientAccountKey)
            self.keyImage = try XCTUnwrap(KeyImage(base64Encoded: Self.keyImageBase64Encoded))
            self.wrongAccountKey = Self.wrongAccountKey()
        }
    }
}

extension TxOut.Fixtures.Default {

    fileprivate static func accountKey(accountIndex: UInt8) -> AccountKey {
        AccountKey.Fixtures.DefaultWithoutFog(accountIndex: accountIndex).accountKey
    }

    fileprivate static func wrongAccountKey() -> AccountKey {
        AccountKey.Fixtures.DefaultWithoutFog(accountIndex: 254).accountKey
    }

    fileprivate static func txOut(accountKey: AccountKey) throws -> TxOut {
        try TransactionBuilder.output(
            publicAddress: accountKey.publicAddress,
            amount: value,
            fogResolver:
                FogResolver.Fixtures.Default(reportUrl: accountKey.fogReportUrl).fogResolver,
            rng: testRngCallback,
            rngContext: TestRng()
        ).get()
    }

    fileprivate static let serializedData = Data(base64Encoded: """
        Ci0KIgog8MbnOGEzPAhctoCv9g2KYxuod3l54dV/satGdD7srH8RvfyTK5L8kv8SIgogJAsm0CReqHeUu10uKzcY8VP\
        xNib30VZh2T78nYuy0xQaIgog1EorWO9UeXpn0XZx+0wdNGAd9wCtNJr39A5ObpnVlC0iVgpUbgYTxUjexTpVTynv91\
        YtSvLT8XyPuxxfV05xwRTjjrGDm1TkuHkCmnzbw3a3ETt6RrNlwLKGfLfgBBkvsI4a8UMl/r21BigZytKZNbZJ52DSs\
        gEA
        """)!

    fileprivate static let keyImageBase64Encoded = "ajrktRQF/zWZapOWeb52jzpCN6BeuQCIBSI0Jo9rYVg="
    fileprivate static let value: UInt64 = 2_499_990_000_000_000

}
