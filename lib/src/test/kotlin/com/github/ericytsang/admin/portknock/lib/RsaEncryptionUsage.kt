package com.github.ericytsang.admin.portknock.lib

import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.Arrays
import javax.crypto.Cipher
import javax.xml.bind.DatatypeConverter

class RsaEncryptionUsage
{
    fun generateKeys():KeyPair
    {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(4096)
        val keyPair = keyGen.generateKeyPair()
        println("encrypt key: ${DatatypeConverter.printHexBinary(keyPair.public.encoded)}")
        println("encrypt key: ${Arrays.toString(keyPair.public.encoded)}")
        println("decrypt key: ${DatatypeConverter.printHexBinary(keyPair.private.encoded)}")
        println("decrypt key: ${Arrays.toString(keyPair.private.encoded)}")
        return keyPair
    }

    @Test
    fun generateKeysTest()
    {
        generateKeys()
    }

    @Test
    fun encryptDecryptTest1()
    {
        val keyPair = generateKeys()
        val message = "hey there".toByteArray()

        // initialize encrypting cipher
        val encryptor = Cipher.getInstance("RSA")
        encryptor.init(Cipher.ENCRYPT_MODE,keyPair.public)

        // encrypt the message
        val encryptedMessage = encryptor.doFinal(message)
        println("encryptedMessage: ${DatatypeConverter.printHexBinary(encryptedMessage)}")

        // initialize decrypting cipher
        val decryptor = Cipher.getInstance("RSA")
        decryptor.init(Cipher.DECRYPT_MODE,keyPair.private)

        // decrypt the message
        val decryptedMessage = decryptor.doFinal(encryptedMessage)
        println("decryptedMessage: ${decryptedMessage.let {String(it)}}")
    }

    @Test
    fun encryptDecryptTest2()
    {
        val keyPair = generateKeys()
        val message = "hey there".toByteArray()

        // initialize encrypting cipher
        val encryptor = Cipher.getInstance("RSA")
        encryptor.init(Cipher.ENCRYPT_MODE,keyPair.private)

        // encrypt the message
        val encryptedMessage = encryptor.doFinal(message)
        println("encryptedMessage: ${DatatypeConverter.printHexBinary(encryptedMessage)}")

        // initialize decrypting cipher
        val decryptor = Cipher.getInstance("RSA")
        decryptor.init(Cipher.DECRYPT_MODE,keyPair.public)

        // decrypt the message
        val decryptedMessage = decryptor.doFinal(encryptedMessage)
        println("decryptedMessage: ${decryptedMessage.let {String(it)}}")
    }
}
