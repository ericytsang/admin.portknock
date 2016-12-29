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
import java.net.InetAddress
import java.security.KeyPair
import java.util.LinkedHashMap
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.DelayQueue
import java.util.concurrent.Delayed
import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import kotlin.concurrent.thread

class PortKnockServer(
    val authorizedClients:Persister,
    val firewall:Firewall,
    val keyPair:KeyPair,
    val knockPort:Int,
    val controlPort:Int,
    val executorService:ExecutorService):Closeable
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
    }

    override fun close()
    {
        gatekeeper.interrupt()
        firewallManipulator.interrupt()
        accepter.interrupt()
    }

    interface Persister
    {
        operator fun get(publicKey:List<Byte>):ClientInfo?
        operator fun set(publicKey:List<Byte>,client:ClientInfo)
        val keys:Set<List<Byte>>
    }

    interface Firewall
    {
        fun allow(connectionSignature:ConnectionSignature)
        fun disallow(connectionSignature:ConnectionSignature)
    }

    data class ConnectionSignature(val remoteIpAddress:InetAddress,val remotePort:Int?,val localPort:Int)
    {
        override fun hashCode():Int
        {
            return remoteIpAddress.hashCode()+localPort
        }

        override fun equals(other:Any?):Boolean
        {
            return other is ConnectionSignature
                && other.remoteIpAddress == remoteIpAddress
                && other.localPort == localPort
                && (other.remotePort == remotePort
                || (other.remotePort == null || remotePort == null))
        }
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
        // fixme: if more are added while this is running, they will not be monitored!
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
                    ?: continue
                val udpPacket = null
                    ?: ipPacket.get(UdpPacket::class.java)
                    ?: continue

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

                // port knock is authorized, notify the accepter and
                // firewall manipulator threads of authorized client
                run {
                    val clientIpAddress = when (ipPacket)
                    {
                        is IpV4Packet -> ipPacket.header.srcAddr
                        is IpV6Packet -> ipPacket.header.srcAddr
                        else -> throw RuntimeException("unhandled case")
                    }
                    val clientSrcPort = udpPacket.header.srcPort.valueAsInt()
                    val connectionSignature = ConnectionSignature(clientIpAddress,clientSrcPort,knockPort)
                    firewallManipulator.allowCommand(connectionSignature,clientInfo,PORT_KNOCK_CLEARANCE_INTERVAL)
                }
            }
        }
    }

    private val firewallManipulator = object:Thread()
    {
        private val delayQueue = DelayQueue<Command>()

        /**
         * used to keep track of how many times each connection signature has
         * been requested to be opened so that when the requests for a
         * connection signature becomes 0 or is changed and was 0, we can
         * properly invoke methods on [firewall] and not accidentally allow or
         * disallow a connection signature multiple times.
         */
        private val openCount = LinkedHashMap<ConnectionSignature,Pair<ClientInfo,Int>>()

        val allowedConnectionSignatures:Map<ConnectionSignature,ClientInfo> get()
        {
            return openCount.mapValues {it.value.first}
        }

        init
        {
            name = "${this@PortKnockServer}.firewallManipulator"
            start()
        }

        fun allowCommand(connectionSignature:ConnectionSignature,clientInfo:ClientInfo,clearanceInterval:Long)
        {
            Command.Open(connectionSignature,clientInfo,clearanceInterval,0)
                .run {delayQueue.put(this)}
        }

        private fun disallowCommand(connectionSignature:ConnectionSignature,clientInfo:ClientInfo,delayMillis:Long)
        {
            Command.Close(connectionSignature,clientInfo,delayMillis)
                .run {delayQueue.put(this)}
        }

        private fun exitCommand()
        {
            Command.Exit(0)
                .run {delayQueue.put(this)}
        }

        override fun interrupt()
        {
            // end thread
            exitCommand()
            join()

            // disallow all allowed connection signatures
            for (connectionSignature in openCount.keys)
            {
                firewall.disallow(connectionSignature)
            }
        }

        override fun run()
        {
            while (true)
            {
                // dequeue commands from delay queue and execute them
                val command = delayQueue.take()
                when (command)
                {
                    is Command.Open ->
                    {
                        // increment request count for connection signature
                        val prev = openCount[command.connectionSignature] ?: command.clientInfo to 0
                        openCount[command.connectionSignature] = prev.copy(second = prev.second+1)

                        // allow connections with the connection signature to
                        // connect only when the count goes from 0 to 1 because
                        // we do not want to allow it multiple times as that can
                        // mess up some firewalls.
                        if (prev.second == 0)
                        {
                            firewall.allow(command.connectionSignature)
                            disallowCommand(command.connectionSignature,command.clientInfo,command.clearanceInterval)
                        }
                        Unit
                    }
                    is Command.Close ->
                    {
                        // decrement request count for connection signature
                        val prev = openCount[command.connectionSignature] ?: throw RuntimeException("counts should never go negative")
                        openCount[command.connectionSignature] = prev.copy(second = prev.second-1)
                        if (openCount[command.connectionSignature]?.second == 0)
                        {
                            openCount.remove(command.connectionSignature)
                        }

                        // disallow connections with the connection signature to
                        // connect only when the count goes from 1 to 0 because
                        // we do not want to disallow it multiple times as that
                        // can mess up some firewalls.
                        if (prev.second == 1)
                        {
                            firewall.disallow(command.connectionSignature)
                        }
                        Unit
                    }
                    is Command.Exit -> return
                }.apply {/*force exhaustive when statement*/}
            }
        }
    }

    private val accepter = object:Thread()
    {
        private val tcpServer = TcpServer(controlPort)

        private var interrupted = false

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
                val connectionSignature = ConnectionSignature(
                    tcpConnection.socket.inetAddress,
                    tcpConnection.socket.port,
                    tcpConnection.socket.localPort)
                try {
                    check(connectionSignature in firewallManipulator.allowedConnectionSignatures.keys)
                } catch (ex:IllegalStateException) {
                    tcpConnection.close()
                    continue
                }

                // authenticate the connection
                val rsaConnection = EncryptedConnection(
                    tcpConnection,
                    firewallManipulator.allowedConnectionSignatures[connectionSignature]!!.publicKey.toByteArray(),
                    keyPair.private.encoded.toList().toByteArray())

                // handle its requests in a separate thread until it disconnects
                thread {ClientSession(rsaConnection,executorService).run()}
            }
        }
    }

    /**
     * commands used by the [firewallManipulator].
     */
    private sealed class Command(timeout:Long):Delayed
    {
        class Open(val connectionSignature:ConnectionSignature,val clientInfo:ClientInfo,val clearanceInterval:Long,delayMillis:Long):Command(delayMillis)
        class Close(val connectionSignature:ConnectionSignature,val clientInfo:ClientInfo,delayMillis:Long):Command(delayMillis)
        class Exit(delayMillis:Long):Command(delayMillis)

        val expireTime = System.currentTimeMillis()+timeout

        override fun compareTo(other:Delayed):Int
        {
            return (getDelay(TimeUnit.MILLISECONDS)-other.getDelay(TimeUnit.MILLISECONDS))
                .coerceIn(-1L..1L)
                .toInt()
        }

        override fun getDelay(unit:TimeUnit):Long
        {
            return unit.convert(expireTime-System.currentTimeMillis(),TimeUnit.MILLISECONDS)
        }
    }
}
