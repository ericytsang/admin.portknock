package com.github.ericytsang.admin.portknock

import java.net.InetAddress

interface Firewall
{
    fun allow(remoteIpAddress:InetAddress,remotePortRange:IntRange,localPort:Int):Boolean
    fun disallow(remoteIpAddress:InetAddress,remotePortRange:IntRange,localPort:Int)
}
