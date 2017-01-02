package admin.portknock

import com.github.ericytsang.lib.concurrent.sleep
import org.junit.Test
import java.net.InetAddress
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.ArrayList

class GeneralTest
{
    val clientKeyPair = generateKeyPair(2048)

    val serverKeyPair = generateKeyPair(4096)

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
            return ClientInfo(100,clientKeyPair.public.encoded.mapTo(ArrayList()){it},"custom client")
        }

        override fun set(publicKey:List<Byte>,client:ClientInfo)
        {
            println("printPersister[${publicKey.hashCode()}] = $client")
        }

        override val keys:Set<List<Byte>>
            get() = throw UnsupportedOperationException() // todo
    }

    val server = PortKnockServer(printPersister,printFirewall,serverKeyPair,51268,62513)

    @Test
    fun doPortKnockAndRequestTcpPortOpen()
    {
        sleep(1000)
        val session = PortKnockClient.connect(
            {println(it)},
            ServerInfo(100,"hellur",InetAddress.getLocalHost(),
                serverKeyPair.public.encoded.mapTo(ArrayList()){it},51268,
                62513),
            clientKeyPair)
        val closeable = session.requestTcpConnectClearance(22)
        sleep(5000)
        closeable.close()
        session.close()
    }

    fun generateKeyPair(keySize:Int):KeyPair
    {
        val keyGen = KeyPairGenerator.getInstance("RSA")
        keyGen.initialize(keySize)
        val keyPair = keyGen.generateKeyPair()
        println("encrypt key: ${keyPair.public.encoded.toHexString()}")
        println("decrypt key: ${keyPair.private.encoded.toHexString()}")
        return keyPair
    }
}
