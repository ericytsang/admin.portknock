package admin.portknock

import com.github.ericytsang.lib.concurrent.sleep
import org.junit.Test
import java.net.InetAddress
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.ArrayList

class GeneralTest
{
    companion object
    {
        val CLIENT_KEY_PAIR = generateKeyPair(2048)

        val SERVER_KEY_PAIR = generateKeyPair(4096)

        const val KNOCK_PORT = 51268

        const val CONTROL_PORT = 62513

        private fun generateKeyPair(keySize:Int):KeyPair
        {
            val keyGen = KeyPairGenerator.getInstance("RSA")
            keyGen.initialize(keySize)
            val keyPair = keyGen.generateKeyPair()
            println("encrypt key: ${keyPair.public.encoded.toHexString()}")
            println("decrypt key: ${keyPair.private.encoded.toHexString()}")
            return keyPair
        }
    }

    val serverAddress = InetAddress.getByName("ennui")

    val printFirewall = object:Firewall
    {
        override fun allow(connectionSignature:Set<ConnectionSignature>)
        {
            println("allow $connectionSignature")
        }

        override fun disallow(connectionSignature:Set<ConnectionSignature>)
        {
            println("disallow $connectionSignature")
        }
    }

    val printPersister = object:PortKnockServer.Persister
    {
        override fun get(publicKey:List<Byte>):ClientInfo?
        {
            println("printPersister[${publicKey.hashCode()}]")
            return ClientInfo(100,CLIENT_KEY_PAIR.public.encoded.mapTo(ArrayList()){it},"custom client")
        }

        override fun set(publicKey:List<Byte>,client:ClientInfo)
        {
            println("printPersister[${publicKey.hashCode()}] = $client")
        }

        override val keys:Set<List<Byte>>
            get() = throw UnsupportedOperationException() // todo
    }

    @Test
    fun server()
    {
        val server = PortKnockServer(printPersister,printFirewall,SERVER_KEY_PAIR,KNOCK_PORT,CONTROL_PORT)
        sleep(120000)
    }

    @Test
    fun client()
    {
        sleep(1000)
        val session = PortKnockClient.connect(
            {println(it)},
            ServerInfo(100,"hellur",serverAddress,
                SERVER_KEY_PAIR.public.encoded.mapTo(ArrayList()){it},
                KNOCK_PORT,CONTROL_PORT),
            CLIENT_KEY_PAIR)
        val closeable = session.requestTcpConnectClearance(22)
        sleep(5000)
        closeable.close()
        session.close()
    }
}
