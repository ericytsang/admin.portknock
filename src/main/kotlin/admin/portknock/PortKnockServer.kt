package admin.portknock

import com.github.ericytsang.lib.net.connection.Connection
import org.pcap4j.core.BpfProgram
import org.pcap4j.core.PacketListener
import org.pcap4j.core.Pcaps
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
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.Cipher
import kotlin.concurrent.thread
import kotlin.concurrent.withLock

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

        const val AUTHENTICATION_TIMEOUT:Long = 20000
    }

    override fun close()
    {
        portKnockListener.interrupt()
        secureServer.close()
    }

    interface Persister
    {
        operator fun get(publicKey:List<Byte>):ClientInfo?
        operator fun set(publicKey:List<Byte>,client:ClientInfo)
        val keys:Set<List<Byte>>
    }

    /**
     * listens for port knocks. notifies the accepter thread upon receiving an
     * authorized port knock.
     */
    private val portKnockListener = object:Thread()
    {
        private val decipherer = Cipher.getInstance("RSA").apply()
        {
            init(Cipher.DECRYPT_MODE,keyPair.private)
        }

        // todo: what if nics are added or removed to or from the computer?
        // fixme: if more are added after this is run, they will not be monitored!
        private val nics = Pcaps.findAllDevs().map() {it.open()}

        private val packets = ArrayBlockingQueue<Packet>(PORT_KNOCK_BACKLOG_Q_SIZE)

        private var interrupted = false

        init
        {
            // listen for UDP packets on all NICs on the knocking port
            val packetListener = PacketListener {packets.put(it)}
            for (nic in nics)
            {
                nic.setFilter("udp[2:2] = $knockPort",BpfProgram.BpfCompileMode.OPTIMIZE)
                thread {
                    // loop forever until...
                    try
                    {
                        nic.loop(-1,packetListener)
                    }

                    // rethrow exception if exited not on purpose
                    catch (ex:Exception)
                    {
                        if (!interrupted) throw ex
                    }
                }
            }

            // start the thread
            name = "${this@PortKnockServer}.gatekeeper"
            start()
        }

        override fun interrupt()
        {
            interrupted = true
            nics.forEach {it.breakLoop()}
            nics.forEach {it.close()}
            super.interrupt()
        }

        override fun run()
        {
            while (true)
            {

                // when a UDP packet is received, check if it is authorized
                val packet = try
                {
                    packets.take()
                }
                catch (ex:Exception)
                {
                    // rethrow exception if exited not on purpose
                    if (!interrupted) throw ex
                    else return
                }
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
                val clientInfo = authorizedClients[encodedPublicKey] ?: continue

                // check that the challenge is as expected
                if (clientInfo.challenge != challenge) continue

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
                allow(connectionSignature,clientInfo)
            }
        }
    }

    // todo: refactor firewall manipulator for readability and maintainabiltiy
    private val firewallManipulators:MutableMap<Set<ConnectionSignature>,FirewallManipulator> = LinkedHashMap()
    private val firewallManipulatorsLock = ReentrantLock()

    private fun allow(connectionSignature:Set<ConnectionSignature>,client:ClientInfo):Unit = firewallManipulatorsLock.withLock()
    {
        val existingThread = firewallManipulators[connectionSignature]
        if (existingThread == null)
        {
            firewallManipulators[connectionSignature] = FirewallManipulator(connectionSignature,client)
        }
        else
        {
            existingThread.renew()
        }
    }

    private inner class FirewallManipulator(val connectionSignatures:Set<ConnectionSignature>,val clientInfo:ClientInfo):Thread()
    {
        init
        {
            name = "${this@PortKnockServer}.gatekeeper.subthread"
            start()
        }

        fun renew()
        {
            require(firewallManipulatorsLock.isHeldByCurrentThread)
            require(firewallManipulators[connectionSignatures] == this)
            interrupt()
        }

        override fun run()
        {
            firewallManipulatorsLock.withLock()
            {
                firewallManipulators[connectionSignatures] = this
                connectionSignatures.forEach {secureServer.authorizedPublicKeys[it] = clientInfo.publicKey.toByteArray()}
                firewall.allow(connectionSignatures)
            }
            while (true)
            {
                try
                {
                    sleep(PORT_KNOCK_CLEARANCE_INTERVAL)
                    break
                }
                catch (ex:InterruptedException)
                {
                    continue
                }
            }
            firewallManipulatorsLock.withLock()
            {
                firewallManipulators.remove(connectionSignatures)
                firewall.disallow(connectionSignatures)
                connectionSignatures.forEach {secureServer.authorizedPublicKeys.remove(it)}
            }
        }
    }

    private val secureServer = object:SecureServer(AUTHENTICATION_TIMEOUT,controlPort,keyPair.private.encoded)
    {
        val authorizedPublicKeys = LinkedHashMap<ConnectionSignature,ByteArray>()

        private val randomGenerator = Random()

        override fun resolvePublicKey(connectionSignature:ConnectionSignature):ByteArray?
        {
            return authorizedPublicKeys[connectionSignature]
        }

        override fun handleConnection(connection:Connection,connectionSignature:ConnectionSignature,publicKey:ByteArray)
        {
            // generate and update challenge for subsequent connection
            run {
                val sign = if (randomGenerator.nextBoolean()) 1 else -1
                val challenge = randomGenerator.nextLong()*sign
                val dataO = connection.outputStream.let(::DataOutputStream)
                dataO.writeLong(challenge)
                dataO.flush()
                val clientInfo = authorizedClients[publicKey.toList()]!!
                authorizedClients[publicKey.toList()] = clientInfo.copy(challenge = challenge)
            }

            // handle its requests in a separate thread until it disconnects
            ClientSession(connection,connectionSignature.remoteIpAddress,firewall)
                .let(::Thread).start()
        }
    }
}
