package com.github.ericytsang.admin.portknock

import java.awt.BorderLayout
import java.awt.Button
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Panel
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import java.util.Properties
import java.util.concurrent.ArrayBlockingQueue
import javax.swing.JFrame
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.table.AbstractTableModel

object PropertiesEditor
{
    private val FRAME_DIMENSIONS = Dimension(300,200)

    /**
     * returns null if the editing was cancelled by the user. returns a
     * new [Properties] object otherwise (not an alias of [properties]).
     */
    fun edit(properties:Properties,jFrameTitle:String):Properties?
    {
        @Suppress("NAME_SHADOWING")
        val properties = properties.clone() as Properties
        val resultQ = ArrayBlockingQueue<()->Properties?>(1)
        val frame = JFrame(jFrameTitle)

        // configure frame size and position
        frame.size = FRAME_DIMENSIONS
        frame.setLocationRelativeTo(null)

        // configure frame close behaviour
        frame.defaultCloseOperation = JFrame.DO_NOTHING_ON_CLOSE
        val windowListener = object:WindowAdapter()
        {
            override fun windowClosing(e:WindowEvent?)
            {
                resultQ.put({null})
            }
        }
        frame.addWindowListener(windowListener)

        // configure frame layout and children
        frame.menuBar = null
        frame.contentPane.layout = BorderLayout()
        val propertiesTable = JTable()
        propertiesTable.fillsViewportHeight = true
        propertiesTable.model = object:AbstractTableModel()
        {
            override fun getRowCount():Int = properties.size
            override fun getColumnCount():Int = 2
            override fun getValueAt(rowIndex:Int,columnIndex:Int):Any
            {
                val key = properties.keys.map(Any::toString).sortedBy {it.toUpperCase()}[rowIndex]
                return when (columnIndex)
                {
                    0 -> key
                    1 -> properties[key] as String
                    else -> throw RuntimeException("unhandled branch")
                }
            }

            override fun isCellEditable(rowIndex:Int,columnIndex:Int):Boolean = columnIndex == 1
            override fun setValueAt(aValue:Any?,rowIndex:Int,columnIndex:Int)
            {
                val key = properties.keys.map(Any::toString).sortedBy {it.toUpperCase()}[rowIndex]
                properties[key] = aValue
            }

            override fun getColumnName(column:Int):String = when (column)
            {
                0 -> "Name"
                1 -> "Value"
                else -> throw RuntimeException("unhandled branch")
            }
        }
        val scrollPane = JScrollPane()
        frame.contentPane.add(scrollPane,BorderLayout.CENTER)
        scrollPane.viewport.view = propertiesTable
        val panel = Panel()
        frame.contentPane.add(panel,BorderLayout.PAGE_END)
        panel.layout = FlowLayout(FlowLayout.TRAILING)
        run {
            val button = Button("OK")
            panel.add(button)
            button.addActionListener {
                propertiesTable.cellEditor?.stopCellEditing()
                resultQ.put({properties})
            }
        }
        run {
            val button = Button("Cancel")
            panel.add(button)
            button.addActionListener {
                resultQ.put({null})
            }
        }

        // show the window
        frame.isVisible = true

        // get the user input, cleanup and return
        val result = resultQ.take().invoke()
        frame.dispose()
        return result
    }
}
