package admin.portknock

import com.github.ericytsang.lib.net.connection.EncryptedConnection
import com.github.ericytsang.lib.net.host.TcpServer
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
import java.util.concurrent.ExecutorService
import javax.crypto.Cipher
import kotlin.concurrent.thread

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
        gatekeeper.interrupt()
        accepter.interrupt()
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
    private val gatekeeper = object:Thread()
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
                thread(name = "${this@PortKnockServer}.gatekeeper.subthread") {
                    val clientIpAddress = when (ipPacket)
                    {
                        is IpV4Packet -> ipPacket.header.srcAddr
                        is IpV6Packet -> ipPacket.header.srcAddr
                        else -> throw RuntimeException("unhandled case")
                    }
                    val clientSrcPort = udpPacket.header.srcPort.valueAsInt()
                    val connectionSignature = ConnectionSignature.createSet(
                        clientIpAddress,clientSrcPort,controlPort)
                    accepter.expectedClientInfos[connectionSignature] = clientInfo
                    firewall.allow(connectionSignature)
                    sleep(PORT_KNOCK_CLEARANCE_INTERVAL)
                    firewall.disallow(connectionSignature)
                    accepter.expectedClientInfos.remove(connectionSignature)
                }
            }
        }
    }

    private val accepter = object:Thread()
    {
        private val tcpServer = TcpServer(controlPort)

        private var interrupted = false

        private val randomGenerator = Random()

        val expectedClientInfos = LinkedHashMap<Set<ConnectionSignature>,ClientInfo>()

        init
        {
            name = "${this@PortKnockServer}.accepter"
            start()
        }

        override fun interrupt()
        {
            interrupted = true
            tcpServer.close()
        }

        override fun run()
        {
            while (true)
            {
                // accept a connection
                val tcpConnection = try
                {
                    tcpServer.accept()
                }
                catch (ex:Exception)
                {
                    // rethrow exception if it is unexpected
                    if (!interrupted) throw ex
                    else return
                }

                // check if the connection is authorized
                val connectionSignature = ConnectionSignature.createSet(
                    tcpConnection.socket.inetAddress,
                    tcpConnection.socket.port,
                    tcpConnection.socket.localPort)
                val clientInfo = expectedClientInfos[connectionSignature]
                if (clientInfo == null)
                {
                    tcpConnection.close()
                    continue
                }

                // authenticate the connection
                val rsaConnection = EncryptedConnection(
                    tcpConnection,
                    clientInfo.publicKey.toByteArray(),
                    keyPair.private.encoded,
                    AUTHENTICATION_TIMEOUT)

                // generate and update challenge for subsequent connection
                run {
                    val sign = if (randomGenerator.nextBoolean()) 1 else -1
                    val challenge = randomGenerator.nextLong()*sign
                    rsaConnection.outputStream.let(::DataOutputStream)
                        .writeLong(challenge)
                    authorizedClients[clientInfo.publicKey] =
                        clientInfo.copy(challenge = challenge)
                }

                // handle its requests in a separate thread until it disconnects
                thread {
                    ClientSession(
                        rsaConnection,
                        tcpConnection.socket.inetAddress,
                        firewall)
                        .run()
                }
            }
        }
    }
}
