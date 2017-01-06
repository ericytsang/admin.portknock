package com.github.ericytsang.admin.portknock.lib.cli

fun getPassword(prompt:String):String
{
    println(prompt)
    return System.console()?.readPassword()?.let {String(it)} ?: readLine()!!
}
