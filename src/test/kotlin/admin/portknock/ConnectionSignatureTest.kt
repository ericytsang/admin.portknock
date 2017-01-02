package admin.portknock

import org.junit.Test
import java.net.InetAddress

class ConnectionSignatureTest
{
    @Test
    fun pseudoSetContains()
    {
        val set = ConnectionSignature.createSet(InetAddress.getLocalHost(),1..4,5)
        assert(ConnectionSignature.createObject(InetAddress.getLocalHost(),0,5) !in set)
        assert(ConnectionSignature.createObject(InetAddress.getLocalHost(),1,5) in set)
        assert(ConnectionSignature.createObject(InetAddress.getLocalHost(),2,5) in set)
        assert(ConnectionSignature.createObject(InetAddress.getLocalHost(),3,5) in set)
        assert(ConnectionSignature.createObject(InetAddress.getLocalHost(),4,5) in set)
        assert(ConnectionSignature.createObject(InetAddress.getLocalHost(),5,5) !in set)
    }

    @Test
    fun pseudoSetSize1()
    {
        val set = ConnectionSignature.createSet(InetAddress.getLocalHost(),1..4,5)
        assert(set.size == 4)
    }

    @Test
    fun pseudoSetSize2()
    {
        val set = ConnectionSignature.createSet(InetAddress.getLocalHost(),1..4,5)
        assert(set.size == set.count())
    }

    @Test
    fun pseudoSetContainsAll()
    {
        val set = ConnectionSignature.createSet(InetAddress.getLocalHost(),1..4,5)
        assert(!set.containsAll(setOf(ConnectionSignature.createObject(InetAddress.getLocalHost(),0,5))))
        assert(!set.containsAll(setOf(
            ConnectionSignature.createObject(InetAddress.getLocalHost(),0,5),
            ConnectionSignature.createObject(InetAddress.getLocalHost(),1,5))
        ))
        assert(set.containsAll(setOf(
            ConnectionSignature.createObject(InetAddress.getLocalHost(),1,5),
            ConnectionSignature.createObject(InetAddress.getLocalHost(),2,5))
        ))
        assert(set.containsAll(setOf(
            ConnectionSignature.createObject(InetAddress.getLocalHost(),1,5),
            ConnectionSignature.createObject(InetAddress.getLocalHost(),2,5),
            ConnectionSignature.createObject(InetAddress.getLocalHost(),3,5),
            ConnectionSignature.createObject(InetAddress.getLocalHost(),4,5))
        ))
        assert(!set.containsAll(setOf(
            ConnectionSignature.createObject(InetAddress.getLocalHost(),4,5),
            ConnectionSignature.createObject(InetAddress.getLocalHost(),5,5))
        ))
    }
}
