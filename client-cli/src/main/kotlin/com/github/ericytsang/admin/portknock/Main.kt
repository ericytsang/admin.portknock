package com.github.ericytsang.admin.portknock

import java.io.Closeable
import java.io.DataInputStream
import java.io.File
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.ArrayList
import java.util.Properties
import java.util.Scanner
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.swing.JOptionPane
import javax.swing.UIManager
import javax.xml.bind.DatatypeConverter

object Main
{
    init
    {
        UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName())
    }

    private val USAGE = ""+
        "usage:\n"+
        "java -jar jarfile.jar list\n"

    private val DATA_DIRECTORY = File(".${File.separator}client_data")
        get()
        {
            if (!field.exists())
            {
                require(field.mkdirs())
            }
            return field
        }

    @JvmStatic fun main(args:Array<String>)
    {
        // edit, print, create, delete, list, connect
        require(args.isNotEmpty()) {USAGE}
        when (args[0])
        {
            "list" -> ServerPersister
                .serverFiles()
                .map {it.name}
                .sortedBy {it.toUpperCase()}
                .forEach(::println)
            "delete" ->
            {
                require(args.size >= 2) {USAGE}
                ServerPersister.delete(args[1])
            }
            "create" ->
            {
                require(args.size >= 2) {USAGE}
                ServerPersister.create(args[1])
            }
            "edit" ->
            {
                require(args.size >= 2) {USAGE}
                ServerPersister.edit(args[1])
            }
            "print" ->
            {
                require(args.size >= 2) {USAGE}
                val serverName = args[1]
                val password = getPassword("Enter password for $serverName:")
                val server = ServerPersister.load(serverName,password)
                println("[${server.friendlyName}]")
                println("${ServerPersister.SERVER_HOSTNAME_KEY} = ${server.hostname}")
                println("${ServerPersister.CHALLENGE_KEY} = ${server.challenge}")
                println("${ServerPersister.PUBLIC_KEY_KEY} = ${server.publicKeyAsRsaPublicKey.encoded.let {DatatypeConverter.printHexBinary(it)}}")
                println("${ServerPersister.KNOCK_PORT_KEY} = ${server.knockPort}")
                println("${ServerPersister.CONTROL_PORT_KEY} = ${server.controlPort}")
            }
            "connect" ->
            {
                require(args.size >= 2) {USAGE}
                val serverName = args[1]
                val password = getPassword("Enter password for $serverName:")
                val server = ServerPersister.load(serverName,password)
                val keypair = KeyPairPersister.loadExistingOrGenerateNewKeyPair()
                val persister = fun(server:ServerInfo):Unit
                {
                    ServerPersister.update(server,password)
                }
                print("connecting...")
                val connection = PortKnockClient.connect(persister,server,keypair)
                println("ok")
                val scanner = Scanner(System.`in`)
                val toggledPorts = mutableMapOf<Int,Closeable>()
                while (true)
                {
                    print("enter port number to toggle open or closed: ")
                    val port = scanner.nextInt()
                    val existing = toggledPorts[port]
                    if (existing != null)
                    {
                        println("port $port closed")
                        existing.close()
                        toggledPorts.remove(port)
                    }
                    else
                    {
                        print("request to open port $port...")
                        val request = connection.requestTcpConnectClearance(port)
                        if (request != null)
                        {
                            toggledPorts[port] = request
                            println("granted")
                        }
                        else
                        {
                            println("denied")
                        }
                    }
                }
            }
        }
    }

    private fun getPassword(prompt:String):String
    {
        println(prompt)
        return System.console()?.readPassword()?.let {String(it)} ?: readLine()!!
    }

    private fun String.to16ByteArray():ByteArray
    {
        require(length > 0)
        var ba = byteArrayOf()
        while (ba.size < 16) ba += toByteArray()
        return ba.copyOf(16)
    }

    private fun Properties.load(password:String,file:File)
    {
        require(file.exists())
        file.inputStream().let(::DataInputStream).use {
            inputStream ->
            val iv = ByteArray(16).apply {inputStream.readFully(this)}.let(::IvParameterSpec)
            val key = password.to16ByteArray().let {SecretKeySpec(it,"AES")}
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE,key,iv)
            val cipherI = CipherInputStream(inputStream,cipher)
            load(cipherI)
            cipherI.close()
        }
    }

    private fun Properties.store(password:String,file:File)
    {
        require(file.parentFile.exists())
        val key = password.to16ByteArray().let {SecretKeySpec(it,"AES")}
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE,key)
        file.outputStream().use {
            outputStream ->
            outputStream.write(cipher.iv)
            val cipherO = CipherOutputStream(outputStream,cipher)
            store(cipherO,"no comment")
            cipherO.close()
        }
    }

    private fun ByteArray.toRsaPrivateKey():PrivateKey
    {
        return KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(this))
    }

    private fun ByteArray.toRsaPublicKey():PublicKey
    {
        return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(this))
    }

    object ServerPersister
    {
        private val SERVER_DIRECTORY = File("${DATA_DIRECTORY.canonicalPath}${File.separator}servers")
            get()
            {
                if (!field.exists())
                {
                    require(field.mkdirs())
                }
                return field
            }

        val PUBLIC_KEY_KEY = "public_key"
        val KNOCK_PORT_KEY = "knock_port"
        val CONTROL_PORT_KEY = "control_port"
        val CHALLENGE_KEY = "challenge"
        val SERVER_HOSTNAME_KEY = "hostname"

        fun serverFiles():List<File>
        {
            return SERVER_DIRECTORY.listFiles().toList()
        }

        fun delete(serverName:String)
        {
            val serverFile = File("${SERVER_DIRECTORY.canonicalPath}${File.separator}$serverName")
            require(serverFile.exists()) {"file does not exists (${serverFile.canonicalPath})"}
            require(serverFile.delete()) {"failed to delete file (${serverFile.canonicalPath})"}
        }

        fun load(serverName:String,password:String):ServerInfo
        {
            // resolve the server properties file name
            val source = File("${SERVER_DIRECTORY.canonicalPath}${File.separator}$serverName")

            // open the server properties file
            val properties = try
            {
                Properties().apply {load(password,source)}
            }
            catch (ex:Exception)
            {
                throw RuntimeException("failed to open the server properties file.",ex)
            }

            // parse the server properties
            return try
            {
                ServerInfo(
                    properties[CHALLENGE_KEY].let {it as String}.toLong(),
                    serverName,
                    properties[SERVER_HOSTNAME_KEY].let {it as String},
                    properties[PUBLIC_KEY_KEY].let {it as String}.let {DatatypeConverter.parseHexBinary(it)}.toList().let {ArrayList(it)},
                    properties[KNOCK_PORT_KEY].let {it as String}.toInt(),
                    properties[CONTROL_PORT_KEY].let {it as String}.toInt())
            }
            catch (ex:Exception)
            {
                throw RuntimeException("failed to parse server property values.",ex)
            }
        }

        fun edit(serverName:String)
        {
            // resolve the server properties file name
            val source = File("${SERVER_DIRECTORY.canonicalPath}${File.separator}$serverName")

            // open and parse the server properties file
            var properties = try
            {
                val password = getPassword("Enter password for $serverName:")
                Properties().apply {load(password,source)}
            }
            catch (ex:Exception)
            {
                throw RuntimeException("failed to open and parse the server properties file.",ex)
            }

            // let user edit the properties object
            properties = getUserInputOrNullUponCancel(properties) ?: return

            // save the properties object if the properties editor returned successfully
            try
            {
                val password = getPassword("Enter new password for $serverName:")
                if (source.exists()) require(source.delete())
                properties.store(password,source)
            }
            catch (ex:Exception)
            {
                throw RuntimeException("failed to save edited properties file.",ex)
            }
        }

        fun update(serverInfo:ServerInfo,password:String)
        {
            // resolve the server properties file name
            val source = File("${SERVER_DIRECTORY.canonicalPath}${File.separator}${serverInfo.friendlyName}")

            // open and parse the server properties file
            val properties = try
            {
                Properties().apply {load(password,source)}
            }
            catch (ex:Exception)
            {
                throw RuntimeException("failed to open and parse the server properties file.",ex)
            }

            // update property fields
            properties[PUBLIC_KEY_KEY] = serverInfo.publicKeyAsRsaPublicKey.encoded.let {DatatypeConverter.printHexBinary(it)}
            properties[KNOCK_PORT_KEY] = serverInfo.knockPort.toString()
            properties[CONTROL_PORT_KEY] = serverInfo.controlPort.toString()
            properties[CHALLENGE_KEY] = serverInfo.challenge.toString()
            properties[SERVER_HOSTNAME_KEY] = serverInfo.hostname

            // save the properties object if the properties editor returned successfully
            try
            {
                if (source.exists()) require(source.delete())
                properties.store(password,source)
            }
            catch (ex:Exception)
            {
                throw RuntimeException("failed to save edited properties file.",ex)
            }
        }

        fun create(serverName:String)
        {
            // resolve the server properties file name
            val destination = File("${SERVER_DIRECTORY.canonicalPath}${File.separator}$serverName")

            // make sure the destination file does not already exist
            if (destination.exists())
            {
                println("a server with the name \"$serverName\" already exists.")
                return
            }

            // create the temporary properties object that the user will edit
            var properties = Properties()
            properties[PUBLIC_KEY_KEY] = "<server public key as a hexadecimal string>"
            properties[KNOCK_PORT_KEY] = "<server port to send the port knock to>"
            properties[CONTROL_PORT_KEY] = "<server port to connect to after port knock>"
            properties[CHALLENGE_KEY] = "<nonce to use in next port knock>"
            properties[SERVER_HOSTNAME_KEY] = "<server IPv4 address, IPv6 address or hostname>"

            // have user edit the properties object
            properties = getUserInputOrNullUponCancel(properties) ?: return

            // save file to server directory
            val password = getPassword("Enter new password for $serverName:")
            properties.store(password,destination)
        }

        private fun getUserInputOrNullUponCancel(properties:Properties):Properties?
        {
            @Suppress("NAME_SHADOWING")
            var properties = properties

            // have the user edit the object until it passes all requirements..
            // once it passes all requirements, return it
            do
            {
                try
                {
                    // have user edit the file
                    properties = PropertiesEditor.edit(properties,"Edit server properties") ?: return null

                    // check if file passes all requirements
                    try
                    {
                        properties.getProperty(PUBLIC_KEY_KEY)
                            ?.let {DatatypeConverter.parseHexBinary(it)}
                            ?: throw NullPointerException()
                    }
                    catch (ex:NullPointerException)
                    {
                        throw IllegalArgumentException("missing key: $PUBLIC_KEY_KEY.")
                    }
                    catch (ex:Exception)
                    {
                        throw IllegalArgumentException("value for $PUBLIC_KEY_KEY must be a hexadecimal number")
                    }
                    try
                    {
                        val knockPort = properties.getProperty(KNOCK_PORT_KEY)
                            ?.toInt()
                            ?: throw NullPointerException()
                        require(knockPort >= 0 && knockPort <= 65535)
                    }
                    catch (ex:NullPointerException)
                    {
                        throw IllegalArgumentException("missing key: $KNOCK_PORT_KEY.")
                    }
                    catch (ex:Exception)
                    {
                        throw IllegalArgumentException("value for $KNOCK_PORT_KEY must be an integer value between 0 and 65535 (inclusive).")
                    }
                    try
                    {
                        val controlPort = properties.getProperty(CONTROL_PORT_KEY)
                            ?.toInt()
                            ?: throw NullPointerException()
                        require(controlPort >= 0 && controlPort <= 65535)
                    }
                    catch (ex:NullPointerException)
                    {
                        throw IllegalArgumentException("missing key: $CONTROL_PORT_KEY.")
                    }
                    catch (ex:Exception)
                    {
                        throw IllegalArgumentException("value for $CONTROL_PORT_KEY must be an integer value between 0 and 65535 (inclusive).")
                    }
                    try
                    {
                        properties.getProperty(CHALLENGE_KEY)
                            ?.toLong()
                            ?: throw NullPointerException()
                    }
                    catch (ex:NullPointerException)
                    {
                        throw IllegalArgumentException("missing key: $CHALLENGE_KEY.")
                    }
                    catch (ex:Exception)
                    {
                        throw IllegalArgumentException("value for $CHALLENGE_KEY must be an integer")
                    }
                    try
                    {
                        properties.getProperty(SERVER_HOSTNAME_KEY)
                            ?: throw NullPointerException()
                    }
                    catch (ex:NullPointerException)
                    {
                        throw IllegalArgumentException("missing key: $SERVER_HOSTNAME_KEY.")
                    }

                    // return the valid properties file
                    return properties
                }
                catch (ex:Exception)
                {
                    require(ex is IllegalArgumentException || ex is NullPointerException)
                    {
                        throw ex
                    }
                    val options = arrayOf("Continue editing","Discard changes")
                    val result = JOptionPane.showOptionDialog(null,
                        ex.message,"Editing Error",
                        JOptionPane.OK_CANCEL_OPTION,
                        JOptionPane.ERROR_MESSAGE,
                        null,options,options[0])
                    if (result == JOptionPane.OK_OPTION)
                    {
                        continue
                    }
                    else
                    {
                        return null
                    }
                }
            }
            while (true)
        }
    }

    object KeyPairPersister
    {
        private val RSA_KEYS_FILE = File("${DATA_DIRECTORY.canonicalPath}${File.separator}rsakeys.keystore")
        private val PUBLIC_KEY_KEY = "public_key"
        private val PRIVATE_KEY_KEY = "private_key"
        private val RSA_KEY_SIZE = 2048

        fun loadExistingOrGenerateNewKeyPair():KeyPair
        {
            // get RSA keys...generate RSA keys if needed
            return if (!KeyPairPersister.doesKeyPairFileExist())
            {
                println("keystore file not found.")
                println("generating RSA keys...")
                val keyPair = KeyPairGenerator.getInstance("RSA")
                    .apply {initialize(RSA_KEY_SIZE)}
                    .generateKeyPair()
                println("saving RSA keys...")
                KeyPairPersister.saveKeyPair(getPassword("Create password for key store:"),keyPair)
                keyPair
            }
            else
            {
                println("keystore file found.")
                println("loading RSA keys...")
                KeyPairPersister.loadKeyPair(getPassword("Enter password for key store:"))
            }
        }

        private fun doesKeyPairFileExist():Boolean
        {
            return RSA_KEYS_FILE.exists()
        }

        private fun saveKeyPair(password:String,keyPair:KeyPair)
        {
            RSA_KEYS_FILE.delete()
            require(!RSA_KEYS_FILE.exists())
            val properties = Properties()
            properties.setProperty(PUBLIC_KEY_KEY,keyPair.public.encoded.let {DatatypeConverter.printHexBinary(it)})
            properties.setProperty(PRIVATE_KEY_KEY,keyPair.private.encoded.let {DatatypeConverter.printHexBinary(it)})
            properties.store(password,RSA_KEYS_FILE)
        }

        private fun loadKeyPair(password:String):KeyPair
        {
            require(RSA_KEYS_FILE.exists())
            val properties = Properties().apply {load(password,RSA_KEYS_FILE)}
            val encodedPublicKey = properties.getProperty(PUBLIC_KEY_KEY).let {DatatypeConverter.parseHexBinary(it)}
            val encodedPrivateKey = properties.getProperty(PRIVATE_KEY_KEY).let {DatatypeConverter.parseHexBinary(it)}
            return KeyPair(encodedPublicKey.toRsaPublicKey(),encodedPrivateKey.toRsaPrivateKey())
        }
    }
}

