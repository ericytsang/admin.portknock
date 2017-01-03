package com.github.ericytsang.admin.portknock

import com.github.ericytsang.lib.modem.Modem
import com.github.ericytsang.lib.net.connection.Connection
import java.io.DataInputStream
import java.net.InetAddress

internal class ClientSession(val connection:Connection,val clientIpAddress:InetAddress,val firewall:Firewall):Runnable
{
    private val modem = Modem(connection)

    override fun run()
    {
        while (true)
        {
            val connection = modem.accept()
            val connectionHandler = ConnectionHandler(connection)
            Thread(connectionHandler).start()
        }
    }

    inner class ConnectionHandler(val connection:Connection):Runnable
    {
        override fun run()
        {
            // read port to allow
            val dataI = connection.inputStream.let(::DataInputStream)
            val portToAllow = dataI.readInt()
            val connectionSignatureToAllow = ConnectionSignature.createSet(clientIpAddress,0..65535,portToAllow)

            // allow the port
            firewall.allow(connectionSignatureToAllow)

            // wait until the connection closes
            while (true)
            {
                try
                {
                    dataI.read()
                }
                catch (ex:Exception)
                {
                    break
                }
            }

            // disallow the port
            firewall.disallow(connectionSignatureToAllow)
        }
    }
}