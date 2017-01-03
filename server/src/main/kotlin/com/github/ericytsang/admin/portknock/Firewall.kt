package com.github.ericytsang.admin.portknock

interface Firewall
{
    fun allow(connectionSignature:Set<ConnectionSignature>)
    fun disallow(connectionSignature:Set<ConnectionSignature>)
}