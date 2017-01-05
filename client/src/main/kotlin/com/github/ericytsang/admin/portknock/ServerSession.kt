package com.github.ericytsang.admin.portknock

import com.github.ericytsang.lib.modem.Modem
import com.github.ericytsang.lib.net.connection.Connection
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream

class ServerSession(val connection:Connection):Closeable
{
    private val modem = Modem(connection)

    /**
     * returns a closeable if the request to open the port was granted; returns
     * null if the request was denied. close the closeable to request the server
     * to close the port.
     */
    fun requestTcpConnectClearance(remotePort:Int):Closeable?
    {
        val connection = modem.connect(Unit)

        // send the port to request to open to server
        val dataO = connection.outputStream.let(::DataOutputStream)
        dataO.writeInt(remotePort)
        dataO.flush()

        // check to see if action is authorized...
        val dataI = connection.inputStream.let(::DataInputStream)
        val authorized = dataI.readBoolean()

        // close connection and return null if not authorized
        return if (!authorized)
        {
            connection.close()
            null
        }

        // return connection otherwise
        else
        {
            connection
        }
    }

    override fun close()
    {
        modem.close()
    }
}
