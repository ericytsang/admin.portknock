package com.github.ericytsang.admin.portknock.server

import java.net.InetAddress

interface Firewall
{
    fun allow(remoteIpAddress:InetAddress,remotePortRange:IntRange,localPort:Int):Boolean
    fun disallow(remoteIpAddress:InetAddress,remotePortRange:IntRange,localPort:Int)
}
