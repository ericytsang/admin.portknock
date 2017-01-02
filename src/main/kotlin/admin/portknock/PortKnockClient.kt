package admin.portknock

import com.github.ericytsang.lib.concurrent.sleep
import com.github.ericytsang.lib.net.connection.Connection
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
    private val MAX_KNOCK_TRY_COUNT:Int = 5

    private val MAX_CONNECT_TRY_COUNT:Int = 10

    /**
     * performs a port knock on the server inferred from [serverInfo] then tries
     * to establish a connection and authenticate with it.
     */
    fun connect(persister:(ServerInfo)->Unit,serverInfo:ServerInfo,keyPair:KeyPair):ServerSession
    {
        for (i in 1..MAX_KNOCK_TRY_COUNT)
        {
            // do the port knock
            val localPort = run {

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
                val udpPacket = DatagramPacket(
                    udpPayload,
                    udpPayload.size,
                    serverInfo.ipAddress,
                    serverInfo.knockPort)

                // do the port knock; send the udp packet
                DatagramSocket().use {
                    udpSocket ->
                    udpSocket.send(udpPacket)
                    udpSocket.localPort
                }
            }

            for (j in 1..MAX_CONNECT_TRY_COUNT)
            {
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
                        PortKnockServer.AUTHENTICATION_TIMEOUT)
                }
                catch (ex:Exception)
                {
                    require(ex is AuthenticationException || ex is TimeoutException)
                    {
                        throw RuntimeException(ex)
                    }
                    sleep(500)
                    continue
                }

                // receive and update challenge for subsequent connection
                val challenge = encryptedConnection.inputStream.let(::DataInputStream).readLong()
                persister(serverInfo.copy(challenge = challenge))

                // return an object representing the connection
                return ServerSession(encryptedConnection)
            }
        }
        throw ConnectException("failed to establish a connection with port knocking server")
    }
}
