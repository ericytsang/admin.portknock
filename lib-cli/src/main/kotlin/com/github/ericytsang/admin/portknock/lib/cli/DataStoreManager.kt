//package com.github.ericytsang.admin.portknock.lib.cli
//
//import java.io.File
//import java.security.KeyPairGenerator
//import java.util.ArrayList
//import java.util.HashMap
//
//class DataStoreManager(val dataFile:File)
//{
//    fun loadExistingOrCreateNew():Pair<DataStore,String>
//    {
//        // get RSA keys...generate RSA keys if needed
//        return if (!dataFile.exists())
//        {
//            println("data store file not found...")
//            println("generating RSA keys...")
//            val keyPair = KeyPairGenerator.getInstance("RSA")
//                .apply {initialize(RSA_KEY_SIZE)}
//                .generateKeyPair()
//            println("creating data store...")
//            val dataStore = DataStore(
//                keyPair.public.encoded.toCollection(ArrayList()),
//                keyPair.private.encoded.toCollection(ArrayList()),
//                0,0,"","","","",HashMap())
//            val password = getPassword("Enter new password for ${dataFile.name}:")
//            store(password,dataStore)
//            dataStore to password
//        }
//        else
//        {
//            println("data store file found...")
//            println("loading data store file...")
//            val password = getPassword("Enter password for ${dataFile.name}:")
//            load(password) to password
//        }
//    }
//
//    fun load(password:String):DataStore
//    {
//        val stream = dataFile
//            .inputStream()
//            .passwordProtected(password)
//            .let(::ObjectInputStream)
//        return stream.use {it.readObject() as DataStore}
//    }
//
//    fun store(password:String,dataStore:DataStore)
//    {
//        val stream = dataFile
//            .outputStream()
//            .passwordProtected(password)
//            .let(::ObjectOutputStream)
//        stream.use {it.writeObject(dataStore)}
//    }
//}
