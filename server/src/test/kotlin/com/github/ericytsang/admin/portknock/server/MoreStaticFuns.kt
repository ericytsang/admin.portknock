package com.github.ericytsang.admin.portknock.server

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

internal fun ByteArray.toRsaPrivateKey():PrivateKey
{
    return KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(this))
}

internal fun ByteArray.toRsaPublicKey():PublicKey
{
    return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(this))
}
