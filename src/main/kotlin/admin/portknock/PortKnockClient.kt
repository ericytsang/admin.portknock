package admin.portknock

import com.github.ericytsang.lib.net.connection.EncryptedConnection
import com.github.ericytsang.lib.net.host.TcpClient
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.security.KeyPair
import javax.crypto.Cipher

object PortKnockClient
{
    /**
     * performs a port knock on the server inferred from [serverInfo] then tries
     * to establish a connection and authenticate with it.
     */
    fun connect(persister:(ServerInfo)->Unit,serverInfo:ServerInfo,keyPair:KeyPair):ServerSession
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
            encryptor.init(Cipher.ENCRYPT_MODE,serverInfo.publicKeyAsPublicKey)
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

        // create a TCP connection with the port knock server
        val tcpConnection = run {
            val serverCtlAddr = TcpClient.Address(serverInfo.ipAddress,serverInfo.controlPort)
            TcpClient.srcPort(localPort).connect(serverCtlAddr)
        }

        // authenticate the connection
        val rsaConnection = EncryptedConnection(
            tcpConnection,
            serverInfo.publicKey.toByteArray(),
            keyPair.private.encoded)

        // receive and update challenge for subsequent connection
        run {
            val challenge = rsaConnection.inputStream.let(::DataInputStream).readLong()
            persister(serverInfo.copy(challenge = challenge))
        }

        // return an object representing the connection
        return ServerSession(rsaConnection)
    }
}
