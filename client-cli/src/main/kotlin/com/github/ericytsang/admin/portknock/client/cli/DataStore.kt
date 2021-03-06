package com.github.ericytsang.admin.portknock.client.cli

import com.github.ericytsang.admin.portknock.client.ServerInfo
import java.io.Serializable
import java.security.KeyFactory
import java.security.KeyPair
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

data class DataStore(
    val publicKey:List<Byte>,
    val privateKey:List<Byte>,
    val servers:Map<String,ServerInfo>)
    :Serializable
{
    val keyPair:KeyPair get() = KeyPair(
        KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(publicKey.toByteArray())),
        KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(privateKey.toByteArray())))
}
