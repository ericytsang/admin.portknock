package admin.portknock

import com.github.ericytsang.lib.modem.Modem
import com.github.ericytsang.lib.net.connection.Connection
import java.io.Closeable
import java.io.DataOutputStream

class ServerSession(val connection:Connection):Closeable
{
    private val modem = Modem(connection)

    fun requestTcpConnectClearance(remotePort:Int):Closeable
    {
        val connection = modem.connect(Unit)
        connection.outputStream.let(::DataOutputStream).use()
        {
            dataO ->

        }// todo
    }

    override fun close()
    {
        modem.close()
    }
}
