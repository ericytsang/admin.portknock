package admin.portknock

import com.github.ericytsang.lib.net.connection.Connection
import com.github.ericytsang.lib.net.connection.EncryptedConnection
import com.github.ericytsang.lib.net.host.TcpServer
import java.io.Closeable
import java.util.LinkedHashSet

abstract class SecureServer(val listenPort:Int):Closeable
{
    override fun close()
    {
        workerThread.interrupt()
        workerThread.join()
    }

    val authorizedConnectionSignatures:MutableSet<ConnectionSignature> = LinkedHashSet()

    protected abstract fun handleConnection(connection:Connection,connectionSignature:ConnectionSignature)

    private val workerThread = object:Thread()
    {
        private val tcpServer = TcpServer(listenPort)

        private var interrupted = false

        init
        {
            name = this@SecureServer.toString()+".workerThread"
            start()
        }

        override fun interrupt()
        {
            interrupted = true
            tcpServer.close()
        }

        override fun run()
        {
            while (true)
            {
                // accept a connection
                val tcpConnection = try
                {
                    tcpServer.accept()
                }
                catch (ex:Exception)
                {
                    // rethrow exception if it is unexpected
                    if (!interrupted) throw ex
                    else return
                }

                // check if the connection is authorized
                val connectionSignature = ConnectionSignature.createObject(
                    tcpConnection.socket.inetAddress,tcpConnection.socket.port,
                    tcpConnection.socket.localPort)
                if (connectionSignature !in authorizedConnectionSignatures)
                {
                    tcpConnection.close()
                    continue
                }

                // pass connection to handler for handling
                handleConnection(tcpConnection,connectionSignature)
            }
        }
    }
}
