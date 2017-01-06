package com.github.ericytsang.admin.portknock

import java.io.Serializable
import java.net.InetAddress
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.util.ArrayList

data class ServerInfo(
    val challenge:Long,
    val friendlyName:String,
    val hostname:String,
    val publicKey:ArrayList<Byte>,
    val knockPort:Int,
    val controlPort:Int)
    :Serializable
{
    val ipAddress:InetAddress by lazy()
    {
        InetAddress.getByName(hostname)
    }

    val publicKeyAsRsaPublicKey:PublicKey get()
    {
        return KeyFactory.getInstance("RSA")
            .generatePublic(X509EncodedKeySpec(publicKey.toByteArray()))
    }
}
