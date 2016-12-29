package admin.portknock

import org.junit.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import javax.crypto.Cipher

class RsaEncryptionUsage
{
    fun generateKeys():KeyPair
    {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(512)
        val keyPair = keyGen.generateKeyPair()
        println("encrypt key: ${keyPair.public.encoded.toHexString()}")
        println("decrypt key: ${keyPair.private.encoded.toHexString()}")
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
        println("encryptedMessage: ${encryptedMessage.toHexString()}")

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
        println("encryptedMessage: ${encryptedMessage.toHexString()}")

        // initialize decrypting cipher
        val decryptor = Cipher.getInstance("RSA")
        decryptor.init(Cipher.DECRYPT_MODE,keyPair.public)

        // decrypt the message
        val decryptedMessage = decryptor.doFinal(encryptedMessage)
        println("decryptedMessage: ${decryptedMessage.let {String(it)}}")
    }
}
