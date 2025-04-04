package org.example.app.config

import org.springframework.stereotype.Component
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.util.Base64
import javax.crypto.Cipher
import jakarta.annotation.PostConstruct

/**
 * Utility class for cryptographic operations.
 * This class provides methods for generating key pairs, encrypting, and decrypting data.
 */
@Component
class CryptoUtils {
    
    private lateinit var keyPair: KeyPair
    
    /**
     * Initialize the key pair on startup.
     */
    @PostConstruct
    fun init() {
        keyPair = generateKeyPair()
    }
    
    /**
     * Generate a new RSA key pair.
     * 
     * @return A new RSA key pair
     */
    private fun generateKeyPair(): KeyPair {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(2048) // Use 2048 bits for good security
        return keyPairGenerator.generateKeyPair()
    }
    
    /**
     * Get the public key encoded as a Base64 string.
     * This is used to send the public key to the client.
     * 
     * @return The public key encoded as a Base64 string
     */
    fun getPublicKeyBase64(): String {
        return Base64.getEncoder().encodeToString(keyPair.public.encoded)
    }
    
    /**
     * Decrypt data using the private key.
     * 
     * @param encryptedData The encrypted data as a Base64 string
     * @return The decrypted data as a string
     */
    fun decrypt(encryptedData: String): String {
        try {
            val cipher = Cipher.getInstance("RSA")
            cipher.init(Cipher.DECRYPT_MODE, keyPair.private)
            
            val encryptedBytes = Base64.getDecoder().decode(encryptedData)
            val decryptedBytes = cipher.doFinal(encryptedBytes)
            
            return String(decryptedBytes)
        } catch (e: Exception) {
            throw RuntimeException("Failed to decrypt data", e)
        }
    }
}