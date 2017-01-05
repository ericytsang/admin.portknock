package com.github.ericytsang.admin.portknock

interface Firewall
{
    fun allow(connectionSignature:Set<ConnectionSignature>):Boolean
    fun disallow(connectionSignature:Set<ConnectionSignature>)
}
