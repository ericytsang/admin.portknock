package com.github.ericytsang.admin.portknock.server.cli

import com.github.ericytsang.admin.portknock.server.ClientInfo
import java.io.Serializable
import java.security.KeyFactory
import java.security.KeyPair
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

data class DataStore(
    val publicKey:List<Byte>,
    val privateKey:List<Byte>,
    val knockPort:Int,
    val controlPort:Int,
    val ipV4AllowCommand:String,
    val ipV6AllowCommand:String,
    val ipV4DisallowCommand:String,
    val ipV6DisallowCommand:String,
    val clients:Map<String,ClientInfo>)
    :Serializable
{
    val keyPair:KeyPair get() = KeyPair(
        KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(publicKey.toByteArray())),
        KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(privateKey.toByteArray())))
}
