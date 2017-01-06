package com.github.ericytsang.admin.portknock

import java.io.Closeable
import java.io.File
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.security.KeyPairGenerator
import java.util.ArrayList
import java.util.HashMap
import java.util.InputMismatchException
import java.util.Properties
import java.util.Scanner
import javax.swing.JOptionPane
import javax.swing.UIManager
import javax.xml.bind.DatatypeConverter

object Main
{
    init
    {
        UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName())
    }

    // todo: finish writing usage message
    private val USAGE = ""+
        "usage:\n"+
        "java -jar jarfile.jar list\n"

    private val DATA_FILE = File(".${File.separator}client-cli-default.data")

    private val RSA_KEY_SIZE = 2048

    @JvmStatic fun main(args:Array<String>)
    {
        val dataStoreManager = DataStoreManager(DATA_FILE)
        val (dataStore,password) = dataStoreManager.loadExistingOrCreateNew()

        // edit, print, create, delete, list, connect
        require(args.isNotEmpty()) {USAGE}
        when (args[0])
        {
            "regenkeys" ->
            {
                val keyPair = KeyPairGenerator.getInstance("RSA")
                    .apply {initialize(RSA_KEY_SIZE)}
                    .generateKeyPair()
                val updatedDataStore = dataStore.copy(
                    publicKey = keyPair.public.encoded.toCollection(ArrayList()),
                    privateKey = keyPair.private.encoded.toCollection(ArrayList()))
                dataStoreManager.store(password,updatedDataStore)
            }
            "printme" ->
            {
                val properties = Properties()
                properties["publicKey"] = dataStore.publicKey.toByteArray().let {DatatypeConverter.printHexBinary(it)}
                properties.store(System.out,"client information")
            }
            "chpasswd" ->
            {
                val newPassword = getPassword("Enter new password for ${DATA_FILE.name}:")
                dataStoreManager.store(newPassword,dataStore)
            }
            "list" -> dataStore.servers.keys
                .sortedBy {it.toUpperCase()}
                .forEach(::println)
            "delete" ->
            {
                require(args.size >= 2) {USAGE}
                val serverName = args[1]
                require(serverName in dataStore.servers.keys) {"no server with the name \"$serverName\" currently exists."}
                val updatedDataStore = dataStore.copy(servers = dataStore.servers.filterKeys {it != serverName})
                dataStoreManager.store(password,updatedDataStore)
            }
            "create" ->
            {
                require(args.size >= 2) {USAGE}
                val serverName = args[1]
                require(serverName !in dataStore.servers.keys) {"a server with the name \"$serverName\" already exists."}
                val properties = ServerPersister.templateProperties()
                val server = ServerPersister.getUserInputOrNullUponCancel(properties,serverName)
                if (server == null)
                {
                    println("operation cancelled")
                    return
                }
                val updatedDataStore = dataStore.copy(servers = dataStore.servers.plus(serverName to server))
                dataStoreManager.store(password,updatedDataStore)
            }
            "edit" ->
            {
                require(args.size >= 2) {USAGE}
                val serverName = args[1]
                val server = dataStore.servers[serverName]
                require(server != null) {"no server with the name \"$serverName\" currently exists."}
                server!!
                val properties = ServerPersister.loadProperties(server)
                val updatedServer = ServerPersister.getUserInputOrNullUponCancel(properties,serverName)
                if (updatedServer == null)
                {
                    println("operation cancelled")
                    return
                }
                val updatedDataStore = dataStore.copy(servers = dataStore.servers.plus(serverName to updatedServer))
                dataStoreManager.store(password,updatedDataStore)
            }
            "print" ->
            {
                require(args.size >= 2) {USAGE}
                val serverName = args[1]
                val server = dataStore.servers[serverName]
                require(server != null) {"no server with the name \"$serverName\" currently exists."}
                server!!
                val properties = ServerPersister.loadProperties(server)
                properties.store(System.out,"[$serverName]")
            }
            "connect" ->
            {
                require(args.size >= 2) {USAGE}
                val serverName = args[1]
                val server = dataStore.servers[serverName]
                require(server != null) {"no server with the name \"$serverName\" currently exists."}
                server!!
                val persister = fun(server:ServerInfo):Unit
                {
                    val updatedDataStore = dataStore.copy(servers = dataStore.servers.plus(serverName to server))
                    dataStoreManager.store(password,updatedDataStore)
                }
                print("connecting...")
                val connection = PortKnockClient.connect(persister,server,dataStore.keyPair)
                println("ok")
                val scanner = Scanner(System.`in`)
                val toggledPorts = mutableMapOf<Int,Closeable>()
                while (true)
                {
                    val port = try
                    {
                        print("enter port number to toggle open or closed: ")
                        scanner.nextInt()
                    }
                    catch (ex:InputMismatchException)
                    {
                        scanner.next()
                        continue
                    }
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

    private class DataStoreManager(val dataFile:File)
    {
        fun loadExistingOrCreateNew():Pair<DataStore,String>
        {
            // get RSA keys...generate RSA keys if needed
            return if (!dataFile.exists())
            {
                println("data store file not found...")
                println("generating RSA keys...")
                val keyPair = KeyPairGenerator.getInstance("RSA")
                    .apply {initialize(RSA_KEY_SIZE)}
                    .generateKeyPair()
                println("creating data store...")
                val dataStore = DataStore(
                    keyPair.public.encoded.toCollection(ArrayList()),
                    keyPair.private.encoded.toCollection(ArrayList()),
                    HashMap())
                val password = getPassword("Enter new password for ${dataFile.name}:")
                store(password,dataStore)
                dataStore to password
            }
            else
            {
                println("data store file found...")
                println("loading data store file...")
                val password = getPassword("Enter password for ${dataFile.name}:")
                load(password) to password
            }
        }

        fun load(password:String):DataStore
        {
            val stream = dataFile
                .inputStream()
                .passwordProtected(password)
                .let(::ObjectInputStream)
            return stream.use {it.readObject() as DataStore}
        }

        fun store(password:String,dataStore:DataStore)
        {
            val stream = dataFile
                .outputStream()
                .passwordProtected(password)
                .let(::ObjectOutputStream)
            stream.use {it.writeObject(dataStore)}
        }
    }

    object ServerPersister
    {
        val PUBLIC_KEY_KEY = "public_key"
        val KNOCK_PORT_KEY = "knock_port"
        val CONTROL_PORT_KEY = "control_port"
        val CHALLENGE_KEY = "challenge"
        val SERVER_HOSTNAME_KEY = "hostname"

        fun templateProperties():Properties
        {
            val properties = Properties()
            properties[PUBLIC_KEY_KEY] = "<server public key as a hexadecimal string>"
            properties[KNOCK_PORT_KEY] = "<server port to send the port knock to>"
            properties[CONTROL_PORT_KEY] = "<server port to connect to after port knock>"
            properties[CHALLENGE_KEY] = "<nonce to use in next port knock>"
            properties[SERVER_HOSTNAME_KEY] = "<server IPv4 address, IPv6 address or hostname>"
            return properties
        }

        fun loadProperties(serverInfo:ServerInfo):Properties
        {
            val properties = Properties()
            properties[PUBLIC_KEY_KEY] = serverInfo.publicKey.toByteArray().let {DatatypeConverter.printHexBinary(it)}
            properties[KNOCK_PORT_KEY] = serverInfo.knockPort.toString()
            properties[CONTROL_PORT_KEY] = serverInfo.controlPort.toString()
            properties[CHALLENGE_KEY] = serverInfo.challenge.toString()
            properties[SERVER_HOSTNAME_KEY] = serverInfo.hostname
            return properties
        }

        fun getUserInputOrNullUponCancel(properties:Properties,serverName:String):ServerInfo?
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
                    val publicKey = try
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

                    val knockPort = try
                    {
                        val knockPort = properties.getProperty(KNOCK_PORT_KEY)
                            ?.toInt()
                            ?: throw NullPointerException()
                        require(knockPort >= 0 && knockPort <= 65535)
                        knockPort
                    }
                    catch (ex:NullPointerException)
                    {
                        throw IllegalArgumentException("missing key: $KNOCK_PORT_KEY.")
                    }
                    catch (ex:Exception)
                    {
                        throw IllegalArgumentException("value for $KNOCK_PORT_KEY must be an integer value between 0 and 65535 (inclusive).")
                    }

                    val controlPort = try
                    {
                        val controlPort = properties.getProperty(CONTROL_PORT_KEY)
                            ?.toInt()
                            ?: throw NullPointerException()
                        require(controlPort >= 0 && controlPort <= 65535)
                        controlPort
                    }
                    catch (ex:NullPointerException)
                    {
                        throw IllegalArgumentException("missing key: $CONTROL_PORT_KEY.")
                    }
                    catch (ex:Exception)
                    {
                        throw IllegalArgumentException("value for $CONTROL_PORT_KEY must be an integer value between 0 and 65535 (inclusive).")
                    }

                    val challenge = try
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

                    val hostname = try
                    {
                        properties.getProperty(SERVER_HOSTNAME_KEY)
                            ?: throw NullPointerException()
                    }
                    catch (ex:NullPointerException)
                    {
                        throw IllegalArgumentException("missing key: $SERVER_HOSTNAME_KEY.")
                    }

                    // return the valid properties file
                    return ServerInfo(challenge,serverName,hostname,publicKey.toCollection(ArrayList()),knockPort,controlPort)
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
}
