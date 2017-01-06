package com.github.ericytsang.admin.portknock

import org.junit.Test
import java.util.Properties

class PropertiesEditorTest
{
    @Test
    fun callTest()
    {
        val properties = Properties()
        properties["hello"] = "goodbye"
        properties["lalala"] = "lelelele"
        properties["dog"] = "cat"
        val result = PropertiesEditor.edit(properties,"Edit me")
        println(result)
        assert(result !== properties)
    }
}
