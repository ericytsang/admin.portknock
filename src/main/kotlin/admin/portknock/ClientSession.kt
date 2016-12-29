package admin.portknock

import com.github.ericytsang.lib.modem.Modem
import com.github.ericytsang.lib.net.connection.Connection
import java.util.concurrent.ExecutorService

class ClientSession(val connection:Connection,val executorService:ExecutorService):Runnable
{
    private val modem = Modem(connection)

    override fun run()
    {
        throw UnsupportedOperationException("not implemented") // todo
    }
}
