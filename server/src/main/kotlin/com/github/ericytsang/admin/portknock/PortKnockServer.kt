package com.github.ericytsang.admin.portknock

import com.github.ericytsang.lib.net.connection.Connection
import com.github.ericytsang.lib.net.connection.EncryptedConnection
import com.github.ericytsang.lib.simplifiedmap.ReadWriteLockedSimplifiedMap
import com.github.ericytsang.lib.simplifiedmap.ReadWriteLockedSimplifiedMapWrapper
import com.github.ericytsang.lib.simplifiedmap.SimplifiedMapWrapper
import org.pcap4j.packet.IpV4Packet
import org.pcap4j.packet.IpV6Packet
import org.pcap4j.packet.Packet
import org.pcap4j.packet.UdpPacket
import java.io.ByteArrayInputStream
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.KeyPair
import java.util.LinkedHashMap
import java.util.Random
import java.util.concurrent.Executors
import javax.crypto.Cipher
import kotlin.concurrent.read
import kotlin.concurrent.write

class PortKnockServer(
    val authorizedClients:Persister,
    val firewall:Firewall,
    val keyPair:KeyPair,
    val knockPort:Int,
    val controlPort:Int):Closeable
{
    companion object
    {
        /**
         * number of potential port knock packets allowed to be buffered to
         * await processing.
         */
        const val PORT_KNOCK_BACKLOG_Q_SIZE:Int = 5

        /**
         * time in milliseconds to allow inbound TCP connections for to the
         * control port when a port knock is successfully conducted.
         */
        const val PORT_KNOCK_CLEARANCE_INTERVAL:Long = 5000

        /**
         * maximum number of connections this server will allow to be connected
         * at the same time.
         */
        val MAX_PARALLEL_SESSIONS:Int = Runtime.getRuntime().availableProcessors()
    }

    override fun close()
    {
        portKnockListener.close()
        secureServer.close()
    }

    interface Persister
    {
        operator fun get(publicKey:List<Byte>):ClientInfo?
        operator fun set(publicKey:List<Byte>,client:ClientInfo)
    }

    /**
     * listens for port knocks. notifies the accepter thread upon receiving an
     * authorized port knock.
     */
    private val portKnockListener = object:NetworkSniffer(PORT_KNOCK_BACKLOG_Q_SIZE,"udp[2:2] = $knockPort")
    {
        private val decipherer = Cipher.getInstance("RSA").apply()
        {
            init(Cipher.DECRYPT_MODE,keyPair.private)
        }

        override fun handlePacket(packet:Packet)
        {
            val ipPacket = null
                ?: packet.get(IpV4Packet::class.java)
                ?: packet.get(IpV6Packet::class.java)
                ?: throw RuntimeException("unknown network-level protocol")
            val udpPacket = null
                ?: ipPacket.get(UdpPacket::class.java)
                ?: throw RuntimeException("unknown transport-level protocol")

            // decrypt the payload
            val (challenge,encodedPublicKey) = run {
                val dataI = decipherer.doFinal(udpPacket.payload.rawData)
                    .let(::ByteArrayInputStream)
                    .let(::DataInputStream)
                val challenge = dataI.readLong()
                val encodedPublicKey = ByteArray(dataI.available())
                dataI.readFully(encodedPublicKey)
                Pair(challenge,encodedPublicKey.toList())
            }

            // check that the public key is white-listed
            val clientInfo = authorizedClients[encodedPublicKey] ?: return

            // check that the challenge is as expected
            if (clientInfo.challenge != challenge) return

            // port knock is authorized, allow the connection signature
            val clientIpAddress = when (ipPacket)
            {
                is IpV4Packet -> ipPacket.header.srcAddr
                is IpV6Packet -> ipPacket.header.srcAddr
                else -> throw RuntimeException("unhandled case")
            }
            val clientSrcPort = udpPacket.header.srcPort.valueAsInt()
            val connectionSignature = ConnectionSignature.createSet(
                clientIpAddress,clientSrcPort,controlPort)
            temporarilyAllow(connectionSignature,clientInfo)
        }
    }

    private val secureServer = object:SecureServer(controlPort,Executors.newFixedThreadPool(MAX_PARALLEL_SESSIONS))
    {
        val connectionSignatureToClientInfo:ReadWriteLockedSimplifiedMap<ConnectionSignature,ClientInfo>
            = LinkedHashMap<ConnectionSignature,ClientInfo>()
            .let {SimplifiedMapWrapper(it)}
            .let {ReadWriteLockedSimplifiedMapWrapper(it)}

        private val randomGenerator = Random()

        override fun isAuthorized(connectionSignature:ConnectionSignature):Boolean
        {
            connectionSignatureToClientInfo.readWriteLock.read {
                return connectionSignature in connectionSignatureToClientInfo.keys
            }
        }

        override fun handleConnection(connection:Connection,connectionSignature:ConnectionSignature)
        {
            val clientInfo = connectionSignatureToClientInfo.readWriteLock.read {
                connectionSignatureToClientInfo[connectionSignature]
            }
            if (clientInfo == null)
            {
                connection.close()
                return
            }

            // connection is established...remove firewall rule now
            disallowNow(setOf(connectionSignature),clientInfo)

            // authenticate the connection
            val encryptedConnection = EncryptedConnection(connection,
                clientInfo.publicKey.toByteArray(),
                keyPair.private.encoded,Constants.AUTHENTICATION_TIMEOUT)

            // generate and update challenge for subsequent connection
            run {
                val sign = if (randomGenerator.nextBoolean()) 1 else -1
                val challenge = randomGenerator.nextLong()*sign
                val dataO = encryptedConnection.outputStream.let(::DataOutputStream)
                dataO.writeLong(challenge)
                dataO.flush()
                authorizedClients[clientInfo.publicKey] = clientInfo.copy(challenge = challenge)
            }

            // handle its requests in a separate thread until it disconnects
            ClientSession(encryptedConnection,connectionSignature.remoteIpAddress,firewall).run()
        }
    }

    private val firewallManipulators:ReadWriteLockedSimplifiedMap<Set<ConnectionSignature>,FirewallManipulator>
        = LinkedHashMap<Set<ConnectionSignature>,FirewallManipulator>()
        .let {SimplifiedMapWrapper(it)}
        .let {ReadWriteLockedSimplifiedMapWrapper(it)}

    private fun temporarilyAllow(connectionSignature:Set<ConnectionSignature>,client:ClientInfo)
    {
        firewallManipulators.readWriteLock.write {
            firewallManipulators[connectionSignature] = firewallManipulators[connectionSignature]
                ?.apply {setSleep(PORT_KNOCK_CLEARANCE_INTERVAL)}
                ?: FirewallManipulator(connectionSignature,client)
        }
    }

    private fun disallowNow(connectionSignature:Set<ConnectionSignature>,client:ClientInfo)
    {
        firewallManipulators.readWriteLock.write {
            firewallManipulators[connectionSignature] = firewallManipulators[connectionSignature]
                ?.apply {setSleep(1)}
                ?: FirewallManipulator(connectionSignature,client)
        }
    }

    private inner class FirewallManipulator(val connectionSignatures:Set<ConnectionSignature>,val clientInfo:ClientInfo):Thread()
    {
        init
        {
            name = "${this@PortKnockServer}.gatekeeper.subthread"
            start()
        }

        private var nextSleep = PORT_KNOCK_CLEARANCE_INTERVAL

        fun setSleep(timeout:Long)
        {
            require(firewallManipulators.readWriteLock.isWriteLockedByCurrentThread)
            require(firewallManipulators[connectionSignatures] == this)
            nextSleep = timeout
            interrupt()
        }

        override fun run()
        {
            firewallManipulators.readWriteLock.write {
                secureServer.connectionSignatureToClientInfo.readWriteLock.write {
                    firewallManipulators[connectionSignatures] = this
                    connectionSignatures.forEach {
                        secureServer.connectionSignatureToClientInfo[it] = clientInfo
                    }
                    firewall.allow(connectionSignatures)
                }
            }
            while (true)
            {
                try
                {
                    sleep(nextSleep)
                    break
                }
                catch (ex:InterruptedException)
                {
                    continue
                }
            }
            firewallManipulators.readWriteLock.write {
                secureServer.connectionSignatureToClientInfo.readWriteLock.write {
                    firewall.disallow(connectionSignatures)
                    connectionSignatures.forEach {
                        secureServer.connectionSignatureToClientInfo[it] = null
                    }
                    firewallManipulators[connectionSignatures] = null
                }
            }
        }
    }
}

