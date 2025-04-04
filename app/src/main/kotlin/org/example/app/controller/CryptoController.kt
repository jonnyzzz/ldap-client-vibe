package org.example.app.controller

import org.example.app.config.CryptoUtils
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Controller for cryptographic operations.
 * This controller provides endpoints for cryptographic operations,
 * such as getting the public key for encryption.
 */
@RestController
class CryptoController(private val cryptoUtils: CryptoUtils) {

    /**
     * Get the public key as a Base64 encoded string.
     * This endpoint is used by the client to get the public key for encrypting data.
     * 
     * @return The public key as a Base64 encoded string
     */
    @GetMapping("/api/crypto/public-key")
    fun getPublicKey(): String {
        return cryptoUtils.getPublicKeyBase64()
    }
}