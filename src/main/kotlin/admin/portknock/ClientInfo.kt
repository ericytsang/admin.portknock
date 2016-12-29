package admin.portknock

import java.io.Serializable
import java.util.ArrayList

data class ClientInfo(val challenge:Long,val publicKey:ArrayList<Byte>,val friendlyName:String):Serializable
