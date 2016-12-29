package admin.portknock

import org.pcap4j.core.PcapHandle
import org.pcap4j.core.PcapNetworkInterface

private val hexArray = "0123456789ABCDEF".toCharArray()

fun ByteArray.toHexString():String
{
    val hexChars = CharArray(size*2)
    for (j in 0..size-1)
    {
        val v = this[j].toInt() and 0xFF
        hexChars[j*2] = hexArray[v.ushr(4)]
        hexChars[j*2+1] = hexArray[v and 0x0F]
    }
    return String(hexChars)
}

fun PcapNetworkInterface.open():PcapHandle
{
    return openLive(65536,PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS,5000)
}
