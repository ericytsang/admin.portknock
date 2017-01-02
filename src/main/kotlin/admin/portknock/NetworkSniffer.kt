package admin.portknock

import org.pcap4j.core.BpfProgram
import org.pcap4j.core.PacketListener
import org.pcap4j.core.Pcaps
import org.pcap4j.packet.Packet
import java.io.Closeable
import java.util.concurrent.ArrayBlockingQueue
import kotlin.concurrent.thread

abstract class NetworkSniffer(val packetBacklogSize:Int,val bpfFilter:String):Closeable
{
    override fun close()
    {
        workerThread.interrupt()
        workerThread.join()
    }

    protected abstract fun handlePacket(packet:Packet)

    private val workerThread = object:Thread()
    {
        // todo: what if nics are added or removed to or from the computer?
        // fixme: if more are added after this is run, they will not be monitored!
        private val nics = Pcaps.findAllDevs().map() {it.open()}

        private val packets = ArrayBlockingQueue<Packet>(packetBacklogSize)

        private var interrupted = false

        init
        {
            // listen for UDP packets on all NICs on the knocking port
            val packetListener = PacketListener {packets.put(it)}
            for (nic in nics)
            {
                nic.setFilter(bpfFilter,BpfProgram.BpfCompileMode.OPTIMIZE)
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
            name = this@NetworkSniffer.toString()+".gatekeeper"
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

                // handle the packet
                handlePacket(packet)
            }
        }
    }
}
