package com.github.ericytsang.admin.portknock

import com.github.ericytsang.lib.cipherstream.CipherInputStream
import com.github.ericytsang.lib.cipherstream.CipherOutputStream
import java.io.DataInputStream
import java.io.InputStream
import java.io.OutputStream
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

private fun String.to16ByteArray():ByteArray
{
    require(length > 0)
    var ba = byteArrayOf()
    while (ba.size < 16) ba += toByteArray()

    val result = ByteArray(16)
    for (i in ba.indices)
    {
        result[i%16] = (result[i%16]+ba[i]).toByte()
    }
    return result
}

fun InputStream.passwordProtected(password:String):InputStream
{
    val inputStream = DataInputStream(this)
    val iv = ByteArray(16).apply {inputStream.readFully(this)}.let(::IvParameterSpec)
    val key = password.to16ByteArray().let {SecretKeySpec(it,"AES")}
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE,key,iv)
    return CipherInputStream(inputStream,cipher)
}

fun OutputStream.passwordProtected(password:String):OutputStream
{
    val key = password.to16ByteArray().let {SecretKeySpec(it,"AES")}
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE,key)
    write(cipher.iv)
    return CipherOutputStream(this,cipher)
}
