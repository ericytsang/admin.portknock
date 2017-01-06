package com.github.ericytsang.admin.portknock

import com.github.ericytsang.lib.net.connection.Connection
import com.github.ericytsang.lib.net.host.TcpServer
import java.io.Closeable
import java.util.concurrent.ExecutorService
import java.util.concurrent.TimeUnit

internal abstract class SecureServer(val listenPort:Int,val executorService:ExecutorService):Closeable
{
    private val tcpServer = TcpServer(listenPort)

    private var interrupted = false

    override fun close()
    {
        interrupted = true
        tcpServer.close()
        executorService.shutdown()
        executorService.awaitTermination(Long.MAX_VALUE,TimeUnit.DAYS)
    }

    protected abstract fun isAuthorized(connectionSignature:ConnectionSignature):Boolean

    protected abstract fun handleConnection(connection:Connection,connectionSignature:ConnectionSignature)

    init
    {
        // submit initial task to executor service for execution
        executorService.submit(AcceptTask())
    }

    private inner class AcceptTask:Runnable
    {
        override fun run()
        {
            // submit another instance of this task upon execution
            executorService.submit(AcceptTask())

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
            if (!isAuthorized(connectionSignature))
            {
                tcpConnection.close()
                return
            }

            // pass connection to handler for handling
            handleConnection(tcpConnection,connectionSignature)
        }
    }
}
