package admin.portknock

import java.net.InetAddress

data class ConnectionSignature private constructor(val remoteIpAddress:InetAddress,val remotePort:Int,val localPort:Int)
{
    companion object
    {
        fun createObject(remoteIpAddress:InetAddress,remotePort:Int,localPort:Int):ConnectionSignature
        {
            return ConnectionSignature(remoteIpAddress,remotePort,localPort)
        }

        fun createSet(remoteIpAddress:InetAddress,remotePorts:IntRange,localPort:Int):Set<ConnectionSignature>
        {
            return remotePorts
                .map {
                    remotePort ->
                    createObject(remoteIpAddress,remotePort,localPort)
                }
                .toSet()
        }

        fun createSet(remoteIpAddress:InetAddress,remotePort:Int,localPort:Int):Set<ConnectionSignature>
        {
            return setOf(createObject(remoteIpAddress,remotePort,localPort))
        }
    }
}
