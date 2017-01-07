package com.github.ericytsang.admin.portknock.client

import com.github.ericytsang.lib.concurrent.sleep
import org.junit.Ignore
import org.junit.Test
import java.security.KeyPair
import java.util.ArrayList

// ignoring test because the execution of the unit tests in this test must be
// coordinated between two computers
@Ignore
class PortKnockClientTest
{
    companion object
    {
        val CLIENT_KEY_PAIR = KeyPair(
            byteArrayOf(48,-127,-97,48,13,6,9,42,-122,72,-122,-9,13,1,1,1,5,0,3,-127,-115,0,48,-127,-119,2,-127,-127,0,-127,-99,-104,5,-11,-98,19,-42,116,105,-70,6,-89,-105,94,82,43,73,61,78,-102,89,64,-33,-71,69,-78,55,-71,-122,-128,43,-63,7,-98,-16,61,-28,57,78,-10,-115,-100,-102,109,6,-10,-101,-63,9,-89,121,-46,61,-52,71,-93,103,120,-18,-56,-128,-47,-74,79,23,-50,-100,55,123,-62,-60,-26,112,-118,20,-117,116,9,-17,120,82,84,27,-90,-87,117,2,-41,-17,-44,75,15,107,105,-38,56,-117,9,-71,7,-46,-110,-17,-8,88,103,30,7,-28,-16,39,21,69,14,13,-84,89,86,-53,50,-13,112,105,-59,89,15,1,2,3,1,0,1).toRsaPublicKey(),
            byteArrayOf(48,-126,2,117,2,1,0,48,13,6,9,42,-122,72,-122,-9,13,1,1,1,5,0,4,-126,2,95,48,-126,2,91,2,1,0,2,-127,-127,0,-127,-99,-104,5,-11,-98,19,-42,116,105,-70,6,-89,-105,94,82,43,73,61,78,-102,89,64,-33,-71,69,-78,55,-71,-122,-128,43,-63,7,-98,-16,61,-28,57,78,-10,-115,-100,-102,109,6,-10,-101,-63,9,-89,121,-46,61,-52,71,-93,103,120,-18,-56,-128,-47,-74,79,23,-50,-100,55,123,-62,-60,-26,112,-118,20,-117,116,9,-17,120,82,84,27,-90,-87,117,2,-41,-17,-44,75,15,107,105,-38,56,-117,9,-71,7,-46,-110,-17,-8,88,103,30,7,-28,-16,39,21,69,14,13,-84,89,86,-53,50,-13,112,105,-59,89,15,1,2,3,1,0,1,2,-127,-128,80,-25,88,123,-25,-53,10,-32,-30,123,23,-27,-115,120,91,36,120,-26,87,65,23,-16,-68,32,-87,89,-118,-101,99,-49,67,115,-116,34,64,-97,-2,81,-43,63,-89,127,-49,15,73,28,126,-109,-53,-45,69,-39,49,84,-25,-116,-109,-65,67,105,-16,119,15,-18,-113,44,-74,3,-56,-5,103,-19,22,38,0,121,16,-60,-56,-105,93,96,46,7,1,-35,71,27,-59,122,124,118,122,-25,43,89,104,119,94,75,-114,-14,76,-91,-7,52,-33,60,123,58,51,95,-60,-115,-121,98,-117,40,-84,-30,-77,24,112,48,31,97,13,-19,2,65,0,-36,-105,-89,-125,-53,-32,-49,-48,20,71,-59,-120,51,109,29,101,58,127,8,-81,-8,-31,111,55,48,-27,3,105,65,-59,127,15,-91,72,38,124,-42,93,-46,118,66,-54,56,-82,-72,69,49,-11,17,-107,-55,116,65,58,24,27,-114,65,2,-68,-66,35,8,-57,2,65,0,-106,107,-98,99,-15,109,95,52,-80,-53,-7,-99,-48,-96,-74,-24,61,3,-63,58,103,59,101,-88,32,-68,80,-110,-114,2,-1,-98,-13,-127,-122,-60,20,123,97,-72,72,-22,113,22,108,-93,118,119,26,-80,3,88,124,-66,84,-23,-101,32,-93,84,77,-74,-79,-9,2,64,66,110,9,44,79,-127,108,19,-91,-121,-41,-100,-92,-97,-1,114,52,-93,124,-30,65,120,-30,29,36,-60,82,-70,-89,-21,-23,-49,-76,94,125,-8,-86,53,-90,-29,-90,73,111,-72,110,21,-88,109,-68,-43,-10,-52,-29,-73,-78,-6,-39,100,10,-122,-4,91,96,-111,2,64,102,-109,30,-32,-62,-101,53,-24,69,-125,-29,69,-74,38,82,116,-114,95,8,30,-98,-107,7,-98,-98,44,44,-71,-77,-13,-31,-126,-16,68,-20,-76,-69,-50,-29,117,122,-21,-68,-112,113,39,11,58,-17,77,6,11,10,-115,-12,115,-107,32,-83,-96,104,-102,100,67,2,64,47,96,-80,82,56,-73,-67,-9,33,31,92,91,-104,44,115,66,42,-104,-19,-44,92,68,-15,102,-12,-76,4,85,-101,-72,-110,63,-62,-44,44,52,-66,-2,54,-31,85,99,-102,35,-123,51,-12,115,-123,92,-4,-11,87,-5,58,-85,-86,-111,72,-55,-1,-39,64,-10).toRsaPrivateKey())

        val SERVER_KEY_PAIR = KeyPair(
            byteArrayOf(48,-126,2,34,48,13,6,9,42,-122,72,-122,-9,13,1,1,1,5,0,3,-126,2,15,0,48,-126,2,10,2,-126,2,1,0,-109,-113,-25,-25,112,89,-56,94,11,-30,50,-124,-1,-4,-85,119,105,45,-30,114,-118,48,18,53,-109,103,-18,-11,23,-37,53,53,-81,-36,40,113,-83,-99,-61,-82,118,47,118,-47,-28,37,60,6,-51,-85,12,-7,20,92,65,-77,-35,-110,70,-114,102,-122,19,-1,-80,90,7,-120,86,-60,56,39,-109,-92,109,91,23,3,119,73,-75,43,-76,-32,76,-102,-72,-34,-32,-47,-53,-1,51,-5,-31,96,-43,103,-74,21,-86,-56,-71,-109,71,44,-12,44,15,68,105,100,104,-75,-20,86,-40,72,31,56,68,104,-51,113,-74,91,87,104,99,-68,-81,125,68,-68,-61,-78,40,-74,96,104,-67,72,-26,72,87,-77,-106,118,94,-89,122,101,-2,-61,32,-71,-52,125,-117,-94,-115,-8,-81,-6,-12,-93,0,74,121,30,-99,-54,64,124,89,40,127,53,46,43,-87,123,-77,-121,-27,98,-45,31,36,-96,32,113,-3,12,-1,118,-69,-82,116,-9,-107,-52,75,112,-98,12,-87,97,99,125,-97,-8,75,40,59,74,75,-70,15,-104,-3,-1,79,20,-76,17,96,-45,-112,126,-7,126,8,-13,-34,-123,87,104,100,-55,-32,-1,-74,-62,-119,100,10,69,28,62,-100,-86,37,-12,16,23,-47,-30,40,-120,35,-81,-77,80,44,106,-3,-52,98,-44,-56,-99,-52,99,-60,123,101,-47,121,-52,28,113,-49,118,-41,4,116,25,102,-104,100,77,6,-85,85,53,27,16,-9,-10,125,77,-12,-101,-10,38,-78,-76,56,127,-105,-22,-89,-119,-37,6,89,34,87,-48,-104,26,-27,-42,-12,61,-84,109,-53,8,40,27,-32,-115,-54,-99,41,-28,-114,54,13,111,-1,-89,-61,4,-60,114,-48,114,78,89,-86,-37,-67,-65,-95,-76,-70,125,53,-109,22,10,-78,95,-126,-101,-68,-84,-81,-57,114,-104,66,15,-43,-60,73,86,103,73,-58,-1,-119,-54,72,84,-19,80,-107,-76,-110,53,-108,-70,62,103,41,108,-58,-48,-109,-100,24,19,97,1,-91,127,-44,-72,-81,-21,2,-61,51,-123,64,77,-1,29,-105,45,22,-123,-25,-27,51,-18,57,-85,43,-39,54,-118,-69,-34,2,-74,-73,-83,32,-30,115,-126,-6,61,-75,93,60,-118,114,120,98,-53,110,-70,10,-91,58,-111,48,-85,-114,23,-106,-69,-78,8,-62,-22,-34,53,18,-54,-121,-10,-45,50,15,-100,109,-65,108,39,98,-28,-40,23,-103,27,76,-34,-74,-106,-52,-113,45,-2,-105,119,98,-84,111,44,110,74,80,49,-46,71,2,3,1,0,1).toRsaPublicKey(),
            byteArrayOf(48,-126,9,68,2,1,0,48,13,6,9,42,-122,72,-122,-9,13,1,1,1,5,0,4,-126,9,46,48,-126,9,42,2,1,0,2,-126,2,1,0,-109,-113,-25,-25,112,89,-56,94,11,-30,50,-124,-1,-4,-85,119,105,45,-30,114,-118,48,18,53,-109,103,-18,-11,23,-37,53,53,-81,-36,40,113,-83,-99,-61,-82,118,47,118,-47,-28,37,60,6,-51,-85,12,-7,20,92,65,-77,-35,-110,70,-114,102,-122,19,-1,-80,90,7,-120,86,-60,56,39,-109,-92,109,91,23,3,119,73,-75,43,-76,-32,76,-102,-72,-34,-32,-47,-53,-1,51,-5,-31,96,-43,103,-74,21,-86,-56,-71,-109,71,44,-12,44,15,68,105,100,104,-75,-20,86,-40,72,31,56,68,104,-51,113,-74,91,87,104,99,-68,-81,125,68,-68,-61,-78,40,-74,96,104,-67,72,-26,72,87,-77,-106,118,94,-89,122,101,-2,-61,32,-71,-52,125,-117,-94,-115,-8,-81,-6,-12,-93,0,74,121,30,-99,-54,64,124,89,40,127,53,46,43,-87,123,-77,-121,-27,98,-45,31,36,-96,32,113,-3,12,-1,118,-69,-82,116,-9,-107,-52,75,112,-98,12,-87,97,99,125,-97,-8,75,40,59,74,75,-70,15,-104,-3,-1,79,20,-76,17,96,-45,-112,126,-7,126,8,-13,-34,-123,87,104,100,-55,-32,-1,-74,-62,-119,100,10,69,28,62,-100,-86,37,-12,16,23,-47,-30,40,-120,35,-81,-77,80,44,106,-3,-52,98,-44,-56,-99,-52,99,-60,123,101,-47,121,-52,28,113,-49,118,-41,4,116,25,102,-104,100,77,6,-85,85,53,27,16,-9,-10,125,77,-12,-101,-10,38,-78,-76,56,127,-105,-22,-89,-119,-37,6,89,34,87,-48,-104,26,-27,-42,-12,61,-84,109,-53,8,40,27,-32,-115,-54,-99,41,-28,-114,54,13,111,-1,-89,-61,4,-60,114,-48,114,78,89,-86,-37,-67,-65,-95,-76,-70,125,53,-109,22,10,-78,95,-126,-101,-68,-84,-81,-57,114,-104,66,15,-43,-60,73,86,103,73,-58,-1,-119,-54,72,84,-19,80,-107,-76,-110,53,-108,-70,62,103,41,108,-58,-48,-109,-100,24,19,97,1,-91,127,-44,-72,-81,-21,2,-61,51,-123,64,77,-1,29,-105,45,22,-123,-25,-27,51,-18,57,-85,43,-39,54,-118,-69,-34,2,-74,-73,-83,32,-30,115,-126,-6,61,-75,93,60,-118,114,120,98,-53,110,-70,10,-91,58,-111,48,-85,-114,23,-106,-69,-78,8,-62,-22,-34,53,18,-54,-121,-10,-45,50,15,-100,109,-65,108,39,98,-28,-40,23,-103,27,76,-34,-74,-106,-52,-113,45,-2,-105,119,98,-84,111,44,110,74,80,49,-46,71,2,3,1,0,1,2,-126,2,1,0,-123,91,-16,45,37,71,-81,34,-9,-64,117,1,-24,76,21,54,-11,18,-89,-19,-10,95,-99,-123,87,-13,-3,108,-6,35,125,-126,72,-82,66,-53,2,42,107,-72,23,77,-84,39,-30,-11,-105,-69,90,82,-75,-123,-62,85,-30,119,72,-49,50,-2,-19,63,77,-127,-82,-126,-98,-2,35,-44,112,31,-84,122,84,-18,-106,-20,-27,-8,-14,72,78,-50,-53,-52,-91,57,-96,-101,90,-81,8,-17,33,-16,30,-51,-3,44,-75,-51,116,-111,-37,40,-112,127,-27,72,97,-85,-126,74,-80,14,-120,-89,29,-73,-1,115,108,0,-47,-38,-39,51,25,-72,100,45,101,90,-25,-51,-14,-89,104,-104,32,65,107,5,-124,101,100,-99,19,-52,110,125,17,114,-115,-9,-3,12,-107,-114,-46,-102,39,-119,57,96,-69,25,-109,63,13,65,-59,103,-36,56,18,71,32,-76,11,23,37,-40,-78,-127,-50,-27,-3,118,-51,-5,-42,-61,-47,121,32,3,121,-24,108,52,87,21,-81,113,39,-1,65,40,62,-45,-22,48,-80,-20,-29,101,-125,69,52,-128,113,-102,-9,102,33,72,-14,-11,30,76,62,-111,15,-47,24,126,-37,95,-21,-3,-114,-47,95,-45,-50,-56,72,-49,121,76,-8,-62,11,107,-22,-51,-99,48,28,-124,122,-116,66,34,84,-36,-81,-91,35,-41,125,47,-3,13,-87,-84,84,93,94,-5,35,-86,-85,54,125,14,-64,25,16,14,-63,4,12,-43,84,62,-128,83,58,83,-4,35,95,85,-29,-105,75,113,58,101,-113,85,-42,-39,73,-6,22,-117,24,8,-64,-64,-39,102,82,62,-60,-25,-107,103,-126,-86,-68,-10,-128,34,-55,28,-85,-91,-47,-68,-19,57,111,37,-73,-123,94,126,84,-126,22,31,-72,-109,-102,46,91,-91,-84,47,-116,-121,81,-18,11,-115,-93,30,58,-102,56,10,-120,63,3,-100,113,-6,72,-53,59,-57,-124,4,-103,-70,-65,-12,112,-6,45,23,37,-124,-103,-19,-87,47,62,-98,40,-123,123,91,94,110,59,87,42,-2,-61,83,-14,-119,122,-65,127,111,-23,-48,-65,-127,-25,-56,-14,42,-7,18,19,-42,-95,103,-42,-114,105,32,-95,-18,-65,21,40,30,82,-126,-59,-3,23,-86,26,-2,57,12,-100,28,4,21,11,105,-61,-95,-77,-44,68,84,-15,77,-117,-58,100,107,-117,-128,-7,-65,-3,-103,-80,110,76,-97,-126,-114,-71,43,56,-22,94,-4,93,-114,-84,14,-56,6,3,81,-61,63,-46,48,38,-20,2,-49,-117,29,-71,-39,2,-126,1,1,0,-43,50,-9,36,-103,-70,-17,35,-35,-94,-14,-2,68,120,33,-16,76,-33,104,42,44,27,-31,47,37,14,-39,41,-96,-88,110,121,14,-19,-27,-116,101,34,79,-88,3,82,-10,48,116,23,70,-36,-91,114,-45,64,-53,59,-117,-110,30,-38,3,45,45,121,72,105,15,33,44,85,-73,53,112,-66,105,-109,-126,8,-78,53,-35,-108,72,-94,100,109,-83,19,-36,-115,76,-18,2,78,-38,76,98,-96,75,72,116,-49,-117,38,-10,-49,117,-81,-116,64,-14,4,-97,-114,-37,-43,48,53,-127,69,85,4,60,17,-34,36,-30,3,88,-118,54,-52,66,57,8,-79,-107,-62,-74,-61,-4,-124,-5,-38,27,40,-89,-99,-48,-109,97,13,55,112,16,-33,-67,-56,-4,-99,35,30,69,37,-89,34,-52,-25,114,6,-12,55,-50,-49,-87,46,-74,18,80,-53,27,58,16,-59,-4,-94,73,105,-17,-60,-40,-49,-53,115,-67,-61,46,-90,-102,63,28,26,-52,-40,-77,68,-39,5,-89,97,100,79,-36,-63,-45,-111,-109,78,-83,-118,-92,35,-69,6,122,-33,114,100,62,-128,-73,48,-29,84,80,80,-63,86,115,66,-126,-121,20,117,106,-39,-54,-32,-103,91,32,-84,-108,-63,-90,-27,21,-109,2,-126,1,1,0,-79,47,-95,-76,-10,63,24,82,-63,81,61,-10,116,-96,18,50,-44,85,126,111,24,-18,5,-69,-98,50,20,88,-102,20,-85,121,3,-106,63,-51,-4,126,27,-41,-20,59,53,-51,24,124,-62,-30,-68,-19,-9,-52,13,-76,49,98,61,10,-50,-70,88,102,-7,-57,-106,-37,-20,-122,-96,-90,79,-115,-54,-53,-126,-61,24,52,60,23,85,60,40,-103,-51,36,-73,83,110,-75,-106,-41,7,21,8,-85,-42,16,0,-8,56,46,-9,105,79,-2,-46,27,54,-104,9,23,-63,84,119,-68,8,-107,-120,95,-96,-115,-50,81,35,-86,-6,-33,33,28,91,-91,26,68,77,-48,20,86,-82,13,19,-2,71,64,-42,37,14,-106,-69,-63,14,29,90,95,83,-98,78,-74,-71,-127,-96,-64,-34,76,87,-93,-39,-85,-10,10,-9,-15,45,-15,40,107,127,-77,-61,75,-80,119,27,-2,67,8,-48,-23,-111,-127,40,-67,-29,-121,-81,-74,108,-115,67,-36,17,-32,-2,-91,72,-108,-80,-58,126,106,-13,24,-15,99,-15,115,-27,-53,-9,-13,-18,-3,69,110,-123,-62,50,91,-106,75,-70,-91,34,76,33,-87,-101,-16,-43,118,-81,-51,-119,-26,-62,-108,-96,-78,-105,36,92,-36,-104,54,-128,-3,2,-126,1,1,0,-67,123,12,87,-59,33,116,-60,-123,-120,-5,57,-84,-108,-80,101,39,-115,46,-64,-68,111,18,-43,-103,-77,-10,-95,-98,-99,-45,-127,88,25,106,-8,58,50,34,101,-118,126,-61,59,17,18,86,-14,103,65,4,44,3,-12,41,-7,117,-34,1,16,-73,-25,-96,-55,110,-98,-25,14,79,67,-7,-83,-31,-101,45,-24,-104,-86,115,2,5,3,-1,9,-46,-41,98,31,91,13,-11,-109,43,68,-44,42,-18,125,-71,3,116,2,-17,60,54,-74,12,-118,-12,13,-45,-39,93,-37,-67,122,-16,39,52,-122,12,-11,60,95,-65,87,-123,-21,97,4,108,-98,-49,-15,52,-50,-41,44,-100,83,124,-102,-67,-92,-122,68,38,73,-75,-23,-49,41,-108,117,-91,-16,-23,66,-89,33,-110,7,2,-30,85,6,38,59,-77,-11,-99,-94,-58,20,51,-47,87,105,12,11,-79,56,-91,109,126,-99,-34,113,46,-40,-113,83,-112,-123,-42,2,79,-8,98,-4,22,-81,73,-76,-104,-59,3,-101,-11,81,93,60,14,-46,-60,-1,26,17,-84,11,-19,126,-74,-39,-68,-117,7,89,-46,118,106,-76,86,-91,79,15,-116,100,-62,41,87,-81,123,-123,-111,95,-56,44,75,127,-42,-67,-67,-100,-64,109,2,-126,1,0,75,-22,-52,-82,108,-109,-68,40,57,12,70,48,66,-24,18,-28,20,118,77,37,-20,-40,-113,60,68,27,-48,-5,-27,-120,-43,-81,-108,9,-36,108,-75,-78,-110,-37,-127,44,29,113,50,-4,-63,-61,-60,-113,113,-116,-52,-110,88,86,111,49,34,66,85,126,73,-89,106,-53,-16,27,-2,-39,67,92,-51,119,69,31,-78,79,47,48,16,37,38,-128,63,-107,107,-73,35,-56,74,72,-9,-113,-37,-105,68,-80,-74,-71,-93,-40,-5,-56,-13,-83,-118,-8,125,-5,-58,105,-105,60,73,-47,23,28,122,-63,-2,88,-61,-3,-97,-6,-78,98,-56,29,14,103,63,73,-28,-51,50,-23,-80,-55,-119,-73,121,112,30,80,-30,95,83,50,-12,-119,63,31,121,4,107,85,127,70,59,74,103,-12,-19,-40,22,123,-57,-128,11,-100,26,-61,41,62,102,8,-17,-76,-114,119,122,87,7,1,-48,1,67,-122,-61,-98,24,-49,26,74,95,88,103,-86,-13,62,35,-35,77,-85,-25,-46,36,120,78,-112,113,93,17,39,71,94,-115,110,-57,7,93,-88,109,71,55,-84,102,73,44,63,116,-30,-119,-55,-46,54,-18,63,92,52,4,-46,10,-83,3,-19,-127,52,-29,84,-31,34,-7,65,2,-126,1,1,0,-58,1,82,-100,113,-50,16,-111,118,-113,-88,89,75,37,-128,3,-20,-77,127,-74,-97,17,56,-76,-77,-58,19,107,69,-58,-14,-80,40,10,-25,95,63,-15,100,42,97,125,106,-21,-42,100,81,94,40,-32,89,-67,-35,98,30,41,-78,-26,29,-3,111,-80,60,91,-124,20,82,-75,102,60,111,-114,1,100,-31,90,98,-26,40,-93,-93,110,110,77,-3,61,-79,-51,109,-32,112,-25,-19,7,26,-113,21,35,80,-111,-89,-75,67,-62,-48,-14,-77,107,108,-38,22,60,87,13,-7,75,115,36,44,124,83,19,112,104,-60,127,-21,-104,-21,38,-80,43,125,72,60,-79,47,100,-106,27,-57,115,91,34,28,91,85,36,20,-54,-121,21,15,-41,119,-97,-94,-5,-20,23,-22,-109,-91,122,67,93,-46,111,-23,1,-79,-57,-6,-84,-60,35,-37,-123,63,-123,-65,104,91,-16,-102,105,85,124,35,80,86,99,67,-57,123,59,55,122,-71,78,88,-15,-79,-80,111,119,1,37,-113,17,53,-22,-83,123,124,32,0,-62,40,47,40,35,50,-49,120,123,44,91,92,-111,27,4,111,-76,52,-106,119,-75,-26,-85,66,-46,53,-2,116,11,-110,-43,90,-33,-15,79,-20,59,117,37).toRsaPrivateKey())

        const val KNOCK_PORT = 51268

        const val CONTROL_PORT = 62513
    }

    val serverHostname = "192.168.1.90"

    @Test
    fun client()
    {
        sleep(1000)
        val session = PortKnockClient.connect(
            {println(it)},
            ServerInfo(100,"hellur",serverHostname,
                SERVER_KEY_PAIR.public.encoded.mapTo(ArrayList()){it},
                KNOCK_PORT,CONTROL_PORT),
            CLIENT_KEY_PAIR)
        println("connected!")
        val closeable = session.requestTcpConnectClearance(22)!!
        sleep(5000)
        closeable.close()
        session.close()
    }
}