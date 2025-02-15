//
//  Copyright (c) 2020-2021 MobileCoin. All rights reserved.
//

// swiftlint:disable multiline_function_chains

@testable import MobileCoin
import XCTest

extension Receipt {
    enum Fixtures {}
}

extension Receipt.Fixtures {
    struct Default {
        let receipt: Receipt

        let serializedData = Self.serializedData
        let accountKey: AccountKey
        let txOutPublicKey: RistrettoPublic
        var txOutPublicKeyData: Data { txOutPublicKey.data }
        let value = Self.value
        var txTombstoneBlockIndex = Self.txTombstoneBlockIndex

        let wrongAccountKey: AccountKey

        init() throws {
            self.receipt = try Self.receipt()
            self.accountKey = Self.accountKey()
            self.txOutPublicKey =
                try XCTUnwrap(RistrettoPublic(base64Encoded: Self.txOutPublicKeyBase64Encoded))
            self.wrongAccountKey = Self.wrongAccountKey()
        }
    }
}

extension Receipt.Fixtures.Default {

    fileprivate static func accountKey() -> AccountKey {
        AccountKey.Fixtures.DefaultWithoutFog(accountIndex: 255).accountKey
    }

    fileprivate static func wrongAccountKey() -> AccountKey {
        AccountKey.Fixtures.DefaultWithoutFog(accountIndex: 254).accountKey
    }

    fileprivate static func receipt() throws -> Receipt {
        let accountKey = self.accountKey()
        return try TransactionBuilder.outputWithReceipt(
            publicAddress: accountKey.publicAddress,
            amount: value,
            tombstoneBlockIndex: 100,
            rng: testRngCallback,
            rngContext: TestRng()
        ).get().receipt
    }

    fileprivate static let serializedData = Data(base64Encoded: """
        CiIKINRKK1jvVHl6Z9F2cftMHTRgHfcArTSa9/QOTm6Z1ZQtEiIKILs8QjK0OPKWykAaUKASWMiqo2Pm+Gte53DqNOR\
        WEzfbGGQiLQoiCiAWtv30lxMC0OOlL0ll2wN9vf+ibhwbs1k0j4fTEXOrJhG3oHdsKB2a/w==
        """)!

    fileprivate static let txOutPublicKeyBase64Encoded =
        "1EorWO9UeXpn0XZx+0wdNGAd9wCtNJr39A5ObpnVlC0="
    fileprivate static let value: UInt64 = 10
    fileprivate static let txTombstoneBlockIndex: UInt64 = 100

}
