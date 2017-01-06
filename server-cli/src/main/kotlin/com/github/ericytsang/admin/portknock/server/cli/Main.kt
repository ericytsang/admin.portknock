package com.github.ericytsang.admin.portknock

import java.io.File
import java.io.ObjectInputStream
import java.io.ObjectOutputStream
import java.net.InetAddress
import java.security.KeyPairGenerator
import java.util.ArrayList
import java.util.HashMap
import java.util.LinkedHashMap
import java.util.Properties
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

    private val RSA_KEY_SIZE = 4096

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
                properties["knockPort"] = dataStore.knockPort.toString()
                properties["controlPort"] = dataStore.controlPort.toString()
                properties["ipV4AllowCommand"] = dataStore.ipV4AllowCommand
                properties["ipV6AllowCommand"] = dataStore.ipV6AllowCommand
                properties["ipV4DisallowCommand"] = dataStore.ipV4DisallowCommand
                properties["ipV6DisallowCommand"] = dataStore.ipV6DisallowCommand
                properties.store(System.out,"server information")
            }
            "editme" ->
            {
                var properties = Properties()
                properties["knockPort"] = dataStore.knockPort.toString()
                properties["controlPort"] = dataStore.controlPort.toString()
                properties["ipV4AllowCommand"] = dataStore.ipV4AllowCommand
                properties["ipV6AllowCommand"] = dataStore.ipV6AllowCommand
                properties["ipV4DisallowCommand"] = dataStore.ipV4DisallowCommand
                properties["ipV6DisallowCommand"] = dataStore.ipV6DisallowCommand

                do
                {
                    // let user edit the properties
                    properties = PropertiesEditor.edit(properties,"editme") ?: return println("operation cancelled")

                    // try to parse properties into updatedDataStore
                    val updatedDataStore = try
                    {
                        dataStore.copy(
                            knockPort = try {properties["knockPort"].toString().toInt()} catch(ex:Exception) {throw RuntimeException("failed to parse \"knockPort\" field.")},
                            controlPort = try {properties["controlPort"].toString().toInt()} catch(ex:Exception) {throw RuntimeException("failed to parse \"controlPort\" field.")},
                            ipV4AllowCommand = try {properties["ipV4AllowCommand"].toString()} catch(ex:Exception) {throw RuntimeException("failed to parse \"ipV4AllowCommand\" field.")},
                            ipV6AllowCommand = try {properties["ipV6AllowCommand"].toString()} catch(ex:Exception) {throw RuntimeException("failed to parse \"ipV6AllowCommand\" field.")},
                            ipV4DisallowCommand = try {properties["ipV4DisallowCommand"].toString()} catch(ex:Exception) {throw RuntimeException("failed to parse \"ipV4DisallowCommand\" field.")},
                            ipV6DisallowCommand = try {properties["ipV6DisallowCommand"].toString()} catch(ex:Exception) {throw RuntimeException("failed to parse \"ipV6DisallowCommand\" field.")})
                    }

                    // if we failed to parse, ask user if they would like to try again...
                    catch (ex:RuntimeException)
                    {
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
                            return
                        }
                    }

                    // store the updatedDataStore
                    dataStoreManager.store(password,updatedDataStore)
                }
                while (true)
            }
            "chpasswd" ->
            {
                val newPassword = getPassword("Enter new password for ${DATA_FILE.name}:")
                dataStoreManager.store(newPassword,dataStore)
            }
            "list" -> dataStore.clients.keys
                .sortedBy {it.toUpperCase()}
                .forEach(::println)
            "delete" ->
            {
                require(args.size >= 2) {USAGE}
                val recordName = args[1]
                require(recordName in dataStore.clients.keys) {"no client with the name \"$recordName\" currently exists."}
                val updatedDataStore = dataStore.copy(clients = dataStore.clients.filterKeys {it != recordName})
                dataStoreManager.store(password,updatedDataStore)
            }
            "create" ->
            {
                require(args.size >= 2) {USAGE}
                val recordName = args[1]
                require(recordName !in dataStore.clients.keys) {"a client with the name \"$recordName\" already exists."}
                val properties = ServerPersister.templateProperties()
                val record = ServerPersister.getUserInputOrNullUponCancel(properties,recordName)
                if (record == null)
                {
                    println("operation cancelled")
                    return
                }
                val updatedDataStore = dataStore.copy(clients = dataStore.clients.plus(recordName to record))
                dataStoreManager.store(password,updatedDataStore)
            }
            "edit" ->
            {
                require(args.size >= 2) {USAGE}
                val recordName = args[1]
                val record = dataStore.clients[recordName]
                require(record != null) {"no client with the name \"$recordName\" currently exists."}
                record!!
                val properties = ServerPersister.loadProperties(record)
                val updatedRecord = ServerPersister.getUserInputOrNullUponCancel(properties,recordName)
                if (updatedRecord == null)
                {
                    println("operation cancelled")
                    return
                }
                val updatedDataStore = dataStore.copy(clients = dataStore.clients.plus(recordName to updatedRecord))
                dataStoreManager.store(password,updatedDataStore)
            }
            "print" ->
            {
                require(args.size >= 2) {USAGE}
                val recordName = args[1]
                val record = dataStore.clients[recordName]
                require(record != null) {"no client with the name \"$recordName\" currently exists."}
                record!!
                val properties = ServerPersister.loadProperties(record)
                properties.store(System.out,"[$recordName]")
            }
            "serve" ->
            {
                val clients = dataStore.clients.values
                    .associate {it.publicKey to it}
                    .let {LinkedHashMap<List<Byte>,ClientInfo>(it)}
                val persister = object:PortKnockServer.Persister
                {
                    override fun get(publicKey:List<Byte>):ClientInfo? = clients[publicKey]
                    override fun set(publicKey:List<Byte>,client:ClientInfo) { clients[publicKey] = client }
                }
                val firewall = object:Firewall
                {
                    override fun allow(remoteIpAddress:InetAddress,remotePortRange:IntRange,localPort:Int):Boolean
                    {
                        println("allow $localPort for $remoteIpAddress:$remotePortRange") // todo
                        return true
                    }

                    override fun disallow(remoteIpAddress:InetAddress,remotePortRange:IntRange,localPort:Int)
                    {
                        println("disallow $localPort for $remoteIpAddress:$remotePortRange") // todo
                    }
                }
                val server = PortKnockServer(persister,firewall,dataStore.keyPair,dataStore.knockPort,dataStore.controlPort)
                println("press enter to stop server")
                readLine()
                print("stopping server...")
                try
                {
                    server.close()
                    println("ok")
                }
                catch (ex:Exception)
                {
                    println("failed")
                    ex.printStackTrace()
                }
                print("saving data...")
                try
                {
                    dataStoreManager.store(password,dataStore.copy(clients = clients.values.associate {it.friendlyName to it}))
                    println("ok")
                }
                catch (ex:Exception)
                {
                    println("failed")
                    ex.printStackTrace()
                }
            }
        }
    }

    private class DataStoreManager(val dataFile:java.io.File)
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
                    keyPair.public.encoded.toCollection(java.util.ArrayList()),
                    keyPair.private.encoded.toCollection(java.util.ArrayList()),
                    0,0,"","","","",HashMap())
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
        val CHALLENGE_KEY = "challenge"

        fun templateProperties():Properties
        {
            val properties = Properties()
            properties[PUBLIC_KEY_KEY] = "<client public key as a hexadecimal string>"
            properties[CHALLENGE_KEY] = "<nonce expected to use in next port knock from client>"
            return properties
        }

        fun loadProperties(clientInfo:ClientInfo):Properties
        {
            val properties = Properties()
            properties[PUBLIC_KEY_KEY] = clientInfo.publicKey.toByteArray().let {DatatypeConverter.printHexBinary(it)}
            properties[CHALLENGE_KEY] = clientInfo.challenge.toString()
            return properties
        }

        fun getUserInputOrNullUponCancel(properties:Properties,clientName:String):ClientInfo?
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
                    properties = PropertiesEditor.edit(properties,"Edit $clientName") ?: return null

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

                    // return the valid properties file
                    return ClientInfo(challenge,publicKey.toCollection(ArrayList()),clientName)
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
