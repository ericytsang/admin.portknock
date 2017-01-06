package com.github.ericytsang.admin.portknock.server

import org.pcap4j.core.PcapHandle
import org.pcap4j.core.PcapNetworkInterface

internal fun PcapNetworkInterface.open():PcapHandle
{
    return openLive(65536,PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS,5000)
}
