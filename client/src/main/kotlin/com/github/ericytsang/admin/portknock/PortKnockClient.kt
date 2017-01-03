package com.github.ericytsang.admin.portknock

import com.github.ericytsang.lib.concurrent.sleep
import com.github.ericytsang.lib.net.connection.EncryptedConnection
import com.github.ericytsang.lib.net.host.TcpClient
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.ConnectException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.security.KeyPair
import java.util.concurrent.TimeoutException
import javax.crypto.Cipher
import javax.security.sasl.AuthenticationException

object PortKnockClient
{
    private val MAX_TRY_COUNT:Int = 5

    private val FAILED_TO_CONNECT_SLEEP_MILLIS:Long = 1000

    /**
     * performs a port knock on the server inferred from [serverInfo] then tries
     * to establish a connection and authenticate with it.
     */
    fun connect(persister:(ServerInfo)->Unit,serverInfo:ServerInfo,keyPair:KeyPair):ServerSession
    {
        // resolve unused local port
        val localPort = DatagramSocket().use {it.localPort}

        for (i in 1..MAX_TRY_COUNT)
        {
            // do the port knock
            run {
                // create the raw data
                val byteO = ByteArrayOutputStream()
                val dataO = DataOutputStream(byteO)
                dataO.writeLong(serverInfo.challenge)
                dataO.write(keyPair.public.encoded)
                val rawData = byteO.toByteArray()

                // encrypt raw data
                val encryptor = Cipher.getInstance("RSA")
                encryptor.init(Cipher.ENCRYPT_MODE,serverInfo.publicKeyAsRsaPublicKey)
                val udpPayload = encryptor.doFinal(rawData)

                // pack encrypted raw data into udp packet
                val udpPacket = DatagramPacket(udpPayload,udpPayload.size,
                    serverInfo.ipAddress,serverInfo.knockPort)

                // do the port knock; send the udp packet
                DatagramSocket(localPort).use {it.send(udpPacket)}
            }

            // create a TCP connection with the port knock server
            val tcpConnection = run {
                val serverCtlAddr = TcpClient.Address(serverInfo.ipAddress,serverInfo.controlPort)
                TcpClient.srcPort(localPort).connect(serverCtlAddr)
            }

            // authenticate the connection
            val encryptedConnection = try
            {
                EncryptedConnection(
                    tcpConnection,
                    serverInfo.publicKey.toByteArray(),
                    keyPair.private.encoded,
                    Constants.AUTHENTICATION_TIMEOUT)
            }
            catch (ex:Exception)
            {
                require(ex is AuthenticationException || ex is TimeoutException)
                {
                    throw RuntimeException(ex)
                }
                sleep(FAILED_TO_CONNECT_SLEEP_MILLIS)
                continue
            }

            // receive and update challenge for subsequent connection
            run {
                val challenge = encryptedConnection.inputStream.let(::DataInputStream).readLong()
                persister(serverInfo.copy(challenge = challenge))
            }

            // return an object representing the connection
            return ServerSession(encryptedConnection)
        }
        throw ConnectException("failed to establish a connection with port knocking server")
    }
}
