package admin.portknock

import com.github.ericytsang.lib.net.host.RsaHost
import com.github.ericytsang.lib.net.host.TcpClient
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.security.KeyPair
import javax.crypto.Cipher

class PortKnockClient(val keyPair:KeyPair)
{
    /**
     * performs a port knock on the server inferred from [serverInfo] then tries
     * to establish a connection and authenticate with it.
     */
    fun connect(serverInfo:ServerInfo):ServerSession
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
            encryptor.init(Cipher.ENCRYPT_MODE,keyPair.public)
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

        // create the secure connection with the port knock server
        val portKnockServerConnection = run {
            val serverCtlAddr = TcpClient.Address(serverInfo.ipAddress,serverInfo.controlPort)
            RsaHost().connect(RsaHost.Address(
                {TcpClient.srcPort(localPort).connect(serverCtlAddr)},
                serverInfo.publicKey,
                keyPair.private.encoded.toList()))
        }

        return ServerSession(portKnockServerConnection)
    }
}
