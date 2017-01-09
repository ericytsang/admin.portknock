package com.github.ericytsang.admin.portknock.lib.cli

import org.junit.Test
import java.util.Properties
import javax.swing.UIManager

class PropertiesEditorTest
{
    @Test
    fun callTest()
    {
        UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName())
        val properties = Properties()
        properties["hello"] = "goodbye"
        properties["lalala"] = "lelelele"
        properties["dog"] = "cat"
        val result = Editor.edit(
            listOf("111:","2:"),
            mapOf("111:" to "value1","2:" to "value2"),
            mapOf("111:" to "hint hinth inth inthin thint hinthin hinth inth inthin thint hinthin hinth inth inthin thint hinthin hinth inth inthin thint hinthin hinth inth inthin thint hinthin hinth inth inthin thint hinthin hinth inth inthin thint hinthin thint hinthi nthint hinthin thint1","2:" to "hint2"),
            "Edit me")
        println(result)
        assert(result !== properties)
    }
}
