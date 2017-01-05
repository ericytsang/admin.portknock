package com.github.ericytsang.admin.portknock

import java.io.Serializable
import java.security.KeyFactory
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

data class DataStore(
    val publicKey:List<Byte>,
    val privateKey:List<Byte>,
    val servers:Map<String,ServerInfo>)
    :Serializable
{
    val keyPair:KeyPair get() = KeyPair(publicKeyAsRsaKey,privateKeyAsRsaKey)

    private val publicKeyAsRsaKey:PublicKey get()
    {
        return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(publicKeyAsByteArray))
    }

    private val privateKeyAsRsaKey:PrivateKey get()
    {
        return KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(privateKeyAsByteArray))
    }

    private val publicKeyAsByteArray:ByteArray get()
    {
        return publicKey.toByteArray()
    }

    private val privateKeyAsByteArray:ByteArray get()
    {
        return privateKey.toByteArray()
    }
}
