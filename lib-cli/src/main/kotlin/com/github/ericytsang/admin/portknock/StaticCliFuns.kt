package com.github.ericytsang.admin.portknock

fun getPassword(prompt:String):String
{
    println(prompt)
    return System.console()?.readPassword()?.let {String(it)} ?: readLine()!!
}
