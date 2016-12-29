package admin.portknock

import org.junit.Test
import java.util.concurrent.DelayQueue
import java.util.concurrent.Delayed
import java.util.concurrent.TimeUnit

class DelayQueueTest
{
    class TestDelay(val delayMillis:Long):Delayed
    {
        val expireTimeMillis = System.currentTimeMillis()+delayMillis

        override fun compareTo(other:Delayed):Int
        {
            return (getDelay(TimeUnit.MILLISECONDS)-other.getDelay(TimeUnit.MILLISECONDS))
                .coerceIn(-1L..1L)
                .toInt()
        }

        override fun getDelay(unit:TimeUnit):Long
        {
            return unit.convert(expireTimeMillis-System.currentTimeMillis(),TimeUnit.MILLISECONDS)
        }
    }

    @Test
    fun generalTest()
    {
        val q = DelayQueue<TestDelay>()
        q.put(TestDelay(500))
        q.put(TestDelay(2000))
        q.put(TestDelay(1000))
        q.put(TestDelay(10))
        while (q.isNotEmpty())
        {
            println(q.take().delayMillis)
        }
    }
}
