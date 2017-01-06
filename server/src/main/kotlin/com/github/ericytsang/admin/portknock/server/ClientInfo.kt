package com.github.ericytsang.admin.portknock.server

import java.io.Serializable
import java.util.ArrayList

data class ClientInfo(val challenge:Long,val publicKey:ArrayList<Byte>,val friendlyName:String):Serializable
