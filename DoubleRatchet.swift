// Extracted verbatim from Phantom Chat (Veilus Digital) for public review.
// Source-available — see LICENSE. Cryptographic logic is unmodified;
// only imports differ from the in-app file.

import Foundation
import Foundation
import CryptoKit

/// Double Ratchet Algorithm implementation (Signal Protocol core)
/// Provides per-message encryption keys and self-healing forward secrecy
/// Note: This is not an actor because it's already protected by CryptoService actor.
/// `nonisolated` so the actor's encrypt/decrypt paths — which call out to
/// this class's init and methods — don't trip the project's default
/// MainActor isolation. The CryptoService actor still owns and serializes
/// access; the class itself is internal-only.
nonisolated class DoubleRatchet {
    enum RatchetError: Error {
        case invalidPublicKey
        case encryptionFailed
        case decryptionFailed
        case keyDerivationFailed
    }
    
    // Root key: Used to derive new chain keys
    var rootKey: SymmetricKey
    
    // Sending chain: Generates keys for outgoing messages
    var sendChainKey: SymmetricKey
    var sendCounter: UInt64 = 0
    
    // Receiving chain: Generates keys for incoming messages
    var receiveChainKey: SymmetricKey
    var receiveCounter: UInt64 = 0
    
    // Diffie-Hellman ratchet keys
    var dhSendKey: P256.KeyAgreement.PrivateKey
    var dhReceiveKey: P256.KeyAgreement.PublicKey

    // Whether to perform a per-message DH ratchet step when an incoming
    // message advertises a new public DH key. v1 (symmetric init) sets
    // this false because both sides hold *deterministic* role-derived
    // ephemerals — running DH between mismatched-but-static keys would
    // derive different chain keys on each side and break decryption.
    // v2 (X3DH) sessions set this true: each side has a real ephemeral
    // and the standard Signal DH ratchet works as intended, giving
    // per-message forward secrecy.
    var useDHRatchet: Bool = false

    // Skipped message keys (for out-of-order message handling)
    private var skippedKeys: [MessageKeyIdentifier: SymmetricKey] = [:]

    init(
        rootKey: SymmetricKey,
        sendChainKey: SymmetricKey,
        receiveChainKey: SymmetricKey,
        dhSendKey: P256.KeyAgreement.PrivateKey,
        dhReceiveKey: P256.KeyAgreement.PublicKey,
        useDHRatchet: Bool = false
    ) {
        self.rootKey = rootKey
        self.sendChainKey = sendChainKey
        self.receiveChainKey = receiveChainKey
        self.dhSendKey = dhSendKey
        self.dhReceiveKey = dhReceiveKey
        self.useDHRatchet = useDHRatchet
    }
    
    // MARK: - Encryption
    
    func encryptMessage(_ plaintext: Data) throws -> EncryptedMessage {
        // Derive message key from current send chain key
        let messageKey = deriveMessageKey(from: sendChainKey, counter: sendCounter)
        
        // Encrypt the message
        let sealed = try AES.GCM.seal(plaintext, using: messageKey)
        guard let ciphertext = sealed.combined else {
            throw RatchetError.encryptionFailed
        }
        
        // Create encrypted message
        let message = EncryptedMessage(
            ciphertext: ciphertext,
            counter: sendCounter,
            dhPublicKey: dhSendKey.publicKey.rawRepresentation
        )
        
        // Advance send chain
        sendChainKey = advanceChainKey(sendChainKey)
        sendCounter += 1
        
        return message
    }
    
    // MARK: - Decryption
    
    func decryptMessage(_ message: EncryptedMessage) throws -> Data {
        // Check if we have a skipped key for this message
        let keyId = MessageKeyIdentifier(
            publicKey: message.dhPublicKey,
            counter: message.counter
        )
        
        if let skippedKey = skippedKeys[keyId] {
            // Use skipped key (out-of-order message)
            skippedKeys.removeValue(forKey: keyId)
            return try decryptWithKey(message.ciphertext, using: skippedKey)
        }
        
        // DH ratchet step: only run for v2 (X3DH) sessions. v1 used
        // deterministic role-derived ephemerals, so the dhSendKey we hold
        // and the dhReceiveKey on the peer's side don't actually share a
        // valid DH relationship — performing the ratchet would diverge
        // chain keys and break decryption. v2 has real ephemerals from
        // X3DH, so the standard Signal DH ratchet works.
        let messageDHKey = try P256.KeyAgreement.PublicKey(rawRepresentation: message.dhPublicKey)
        if useDHRatchet,
           messageDHKey.rawRepresentation != dhReceiveKey.rawRepresentation {
            try performDHRatchet(newPublicKey: messageDHKey)
        }
        
        // Skip messages if counter jumped (store skipped keys)
        while receiveCounter < message.counter {
            let skippedKey = deriveMessageKey(from: receiveChainKey, counter: receiveCounter)
            let skippedKeyId = MessageKeyIdentifier(
                publicKey: message.dhPublicKey,
                counter: receiveCounter
            )
            skippedKeys[skippedKeyId] = skippedKey
            
            receiveChainKey = advanceChainKey(receiveChainKey)
            receiveCounter += 1
        }
        
        // Derive message key and decrypt
        let messageKey = deriveMessageKey(from: receiveChainKey, counter: receiveCounter)
        let plaintext = try decryptWithKey(message.ciphertext, using: messageKey)
        
        // Advance receive chain
        receiveChainKey = advanceChainKey(receiveChainKey)
        receiveCounter += 1
        
        return plaintext
    }
    
    // MARK: - DH Ratchet
    
    private func performDHRatchet(newPublicKey: P256.KeyAgreement.PublicKey) throws {
        // Update receive key
        dhReceiveKey = newPublicKey
        
        // Compute new DH shared secret
        let sharedSecret = try dhSendKey.sharedSecretFromKeyAgreement(with: dhReceiveKey)
        
        // Derive new root key and receive chain key
        let (newRootKey, newReceiveChainKey) = deriveRootAndChainKeys(from: sharedSecret)
        rootKey = newRootKey
        receiveChainKey = newReceiveChainKey
        receiveCounter = 0
        
        // Generate new send key pair
        dhSendKey = P256.KeyAgreement.PrivateKey()
        
        // Compute new send DH
        let sendSharedSecret = try dhSendKey.sharedSecretFromKeyAgreement(with: dhReceiveKey)
        
        // Derive new send chain key
        let (newSendRootKey, newSendChainKey) = deriveRootAndChainKeys(from: sendSharedSecret)
        rootKey = newSendRootKey
        sendChainKey = newSendChainKey
        sendCounter = 0
    }
    
    // MARK: - Key Derivation
    
    private func deriveMessageKey(from chainKey: SymmetricKey, counter: UInt64) -> SymmetricKey {
        // Message Key = HKDF(chain_key, "message-key" || counter)
        var info = Data("message-key".utf8)
        info.append(withUnsafeBytes(of: counter.bigEndian) { Data($0) })
        
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: chainKey,
            salt: Data(),
            info: info,
            outputByteCount: 32
        )
    }
    
    private func advanceChainKey(_ chainKey: SymmetricKey) -> SymmetricKey {
        // Next Chain Key = HKDF(chain_key, "chain-key-advancement")
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: chainKey,
            salt: Data(),
            info: Data("chain-key-advancement".utf8),
            outputByteCount: 32
        )
    }
    
    private func deriveRootAndChainKeys(from sharedSecret: SharedSecret) -> (SymmetricKey, SymmetricKey) {
        // Root Key = HKDF(shared_secret, "root-key")
        let newRootKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: rootKey.withUnsafeBytes { Data($0) },
            sharedInfo: Data("root-key".utf8),
            outputByteCount: 32
        )
        
        // Chain Key = HKDF(shared_secret, "chain-key")
        let newChainKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: rootKey.withUnsafeBytes { Data($0) },
            sharedInfo: Data("chain-key".utf8),
            outputByteCount: 32
        )
        
        return (newRootKey, newChainKey)
    }
    
    private func decryptWithKey(_ ciphertext: Data, using key: SymmetricKey) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: ciphertext)
        return try AES.GCM.open(sealedBox, using: key)
    }
}

// MARK: - Supporting Types

// `nonisolated` so the synthesized Hashable conformance is usable
// from the (nonisolated) DoubleRatchet class.
nonisolated struct MessageKeyIdentifier: Hashable {
    let publicKey: Data
    let counter: UInt64
}

// `nonisolated` so the synthesized Codable conformance is available from
// any actor (Firestore writers, CryptoService send/receive, etc.). The
// project's default MainActor isolation would otherwise force every
// encoder/decoder call site to hop.
nonisolated struct EncryptedMessage: Codable {
    let ciphertext: Data
    let counter: UInt64
    let dhPublicKey: Data
}
