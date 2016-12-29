package admin.portknock

import java.io.Serializable
import java.net.InetAddress
import java.util.ArrayList

data class ServerInfo(val challenge:Long,val friendlyName:String,val ipAddress:InetAddress,val publicKey:ArrayList<Byte>,val knockPort:Int,val controlPort:Int):Serializable
