package com.github.ericytsang.admin.portknock

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
            return PseudoSet(remoteIpAddress,remotePorts,localPort)
        }

        fun createSet(remoteIpAddress:InetAddress,remotePort:Int,localPort:Int):Set<ConnectionSignature>
        {
            return setOf(createObject(remoteIpAddress,remotePort,localPort))
        }
    }

    private class PseudoSet(val remoteIpAddress:InetAddress,val remotePorts:IntRange,val localPort:Int):Set<ConnectionSignature>
    {
        override val size:Int get() = remotePorts.last-remotePorts.first+1

        override fun contains(element:ConnectionSignature):Boolean
        {
            return element.remoteIpAddress == remoteIpAddress
                && element.remotePort in remotePorts
                && element.localPort == localPort
        }

        override fun containsAll(elements:Collection<ConnectionSignature>):Boolean
        {
            return elements.all {contains(it)}
        }

        override fun isEmpty():Boolean
        {
            return size == 0
        }

        override fun iterator():Iterator<ConnectionSignature>
        {
            return CustomIterator()
        }

        private inner class CustomIterator:AbstractIterator<ConnectionSignature>()
        {
            val remotePortsIterator = remotePorts.iterator()
            override fun computeNext()
            {
                if (remotePortsIterator.hasNext())
                {
                    setNext(createObject(remoteIpAddress,remotePortsIterator.next(),localPort))
                }
                else
                {
                    done()
                }
            }
        }
    }
}
