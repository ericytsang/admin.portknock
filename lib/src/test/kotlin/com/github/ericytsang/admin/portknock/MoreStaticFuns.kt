package com.github.ericytsang.admin.portknock

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

private val hexArray = "0123456789ABCDEF".toCharArray()

internal fun ByteArray.toHexString():String
{
    val hexChars = CharArray(size*2)
    for (j in 0..size-1)
    {
        val v = this[j].toInt() and 0xFF
        hexChars[j*2] = hexArray[v.ushr(4)]
        hexChars[j*2+1] = hexArray[v and 0x0F]
    }
    return String(hexChars)
}
