package com.github.ericytsang.admin.portknock.lib.cli

import java.awt.Dimension
import java.awt.Font
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.event.FocusAdapter
import java.awt.event.FocusEvent
import java.awt.event.WindowAdapter
import java.awt.event.WindowEvent
import java.util.HashMap
import java.util.concurrent.ArrayBlockingQueue
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JFrame
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextField
import javax.swing.JTextPane

abstract class Editor<Obj>
{
    companion object
    {
        private val FRAME_WIDTH = 300
        private val FRAME_EXTRA_HEIGHT = 100

        /**
         * returns null if the editing was cancelled by the user. returns a
         * new [Properties] object otherwise (not an alias of [values]).
         */
        fun edit(keys:List<String>,values:Map<String,String>?,hints:Map<String,String>?,jFrameTitle:String):Map<String,String>?
        {
            // vetting arguments and generating default values
            require(keys.toSet().size == keys.size)
            @Suppress("NAME_SHADOWING")
            val values:Map<String,String> = HashMap(values ?: keys.associate {it to ""})
            require(keys.toSet() == values.keys)
            @Suppress("NAME_SHADOWING")
            val hints:Map<String,String> = HashMap(hints ?: keys.associate {it to ""})
            require(keys.toSet() == hints.keys)

            val resultQ = ArrayBlockingQueue<()->Map<String,String>?>(1)

            // configure form components
            val formComponents = run {
                val formComponents = mutableListOf<Pair<JLabel,JTextField>>()
                for (key in keys)
                {
                    val textField = JTextField()
                    textField.size = textField.preferredSize
                    textField.maximumSize = Dimension(Int.MAX_VALUE,textField.minimumSize.height)
                    val label = JLabel(key)
                    label.size = label.preferredSize
                    label.horizontalAlignment = JLabel.TRAILING
                    formComponents += label to textField
                }
                formComponents
            }

            // configure button panel
            val buttonPanel = JPanel()
            buttonPanel.layout = GridBagLayout()
            run {
                val c = GridBagConstraints()
                c.weightx = 1.0
                c.fill = GridBagConstraints.HORIZONTAL
                c.gridx = GridBagConstraints.RELATIVE
                buttonPanel.add(JPanel(),c)
            }
            run {
                val c = GridBagConstraints()
                c.gridx = GridBagConstraints.RELATIVE
                val button = JButton("OK")
                buttonPanel.add(button,c)
                button.addActionListener {
                    val result = formComponents.associate {it.first.text to it.second.text}
                    resultQ.put({result})
                }
            }
            run {
                val c = GridBagConstraints()
                c.gridx = GridBagConstraints.RELATIVE
                val button = JButton("Cancel")
                buttonPanel.add(button,c)
                button.addActionListener {
                    resultQ.put({null})
                }
            }

            // configure root
            val root = JPanel(GridBagLayout())
            root.border = BorderFactory.createEmptyBorder(4,4,4,4)
            for ((label,textField) in formComponents)
            {
                // add the label to the form
                run {
                    val c = GridBagConstraints()
                    c.anchor = GridBagConstraints.LINE_END
                    c.gridwidth = GridBagConstraints.RELATIVE
                    root.add(label,c)
                }

                // add the text field to the form
                run {
                    val c = GridBagConstraints()
                    c.weightx = 1.0
                    c.fill = GridBagConstraints.HORIZONTAL
                    c.gridwidth = GridBagConstraints.REMAINDER
                    c.insets = Insets(0,0,4,0)
                    root.add(textField,c)
                }
            }
            run {
                val c = GridBagConstraints()
                c.weighty = 1.0
                c.fill = GridBagConstraints.BOTH
                c.gridwidth = GridBagConstraints.REMAINDER
                c.insets = Insets(0,0,4,0)
                val hint = JTextPane()
                hint.font = Font(Font.SANS_SERIF,Font.ITALIC,hint.font.size)
                hint.background = root.background
                root.add(JScrollPane(hint),c)
                for ((label,textField) in formComponents)
                {
                    textField.addFocusListener(object:FocusAdapter()
                    {
                        override fun focusGained(e:FocusEvent?)
                        {
                            hint.text = hints[label.text]
                        }
                    })
                }
            }
            run {
                val c = GridBagConstraints()
                c.fill = GridBagConstraints.HORIZONTAL
                c.gridwidth = GridBagConstraints.REMAINDER
                root.add(buttonPanel,c)
            }

            // configure frame
            val frame = JFrame(jFrameTitle)
            frame.defaultCloseOperation = JFrame.DO_NOTHING_ON_CLOSE
            val windowListener = object:WindowAdapter()
            {
                override fun windowClosing(e:WindowEvent?)
                {
                    resultQ.put({null})
                }
            }
            frame.addWindowListener(windowListener)
            frame.menuBar = null
            frame.contentPane = root
            frame.isVisible = true
            frame.size = Dimension(FRAME_WIDTH,frame.preferredSize.height)
            frame.minimumSize = Dimension(FRAME_WIDTH,FRAME_EXTRA_HEIGHT+frame.preferredSize.height)
            frame.setLocationRelativeTo(null)

            // get the user input, cleanup and return
            val result = resultQ.take().invoke()
            frame.dispose()
            return result
        }
    }

    /**
     * list of keys in the order that they should be displayed in the GUI.
     */
    protected abstract val keys:List<String>

    /**
     * maps keys to their hint texts to be shown on the GUI if null is passed to
     * [openEditUi].
     */
    protected abstract val hints:Map<String,String>

    /**
     * converts an instance of [Obj] to a [Map] that can be parsed by the GUI.
     */
    protected abstract fun Obj.convert():Map<String,String>

    /**
     * converts an instance of [Map] to an [Obj] that can be used by the
     * program. if the input is of invalid format, throw an
     * [InputFormatException]. messages in [InputFormatException] will be shown
     * to the user in an error dialog, and will be used to give users additional
     * opportunities to correct their input format.
     */
    protected abstract fun Map<String,String>.convert():Obj

    /**
     * opens the editor gui to let the user edit [obj]. if [obj] is null, then
     * [hints] will be used to populate the editor gui; [convert] is
     * used otherwise to generate the values to be displayed in the gui. the
     * other [convert] is used to convert the user inputted values back into an
     * [Obj] which is returned back to the caller. null can be returned to the
     * caller if the user cancels the operation.
     */
    fun openEditUi(obj:Obj?,windowTitle:String):Obj?
    {
        @Suppress("NAME_SHADOWING")
        var obj = obj

        // have the user edit the object until it passes all requirements..
        // once it passes all requirements, return it
        do
        {
            try
            {
                // have user edit the file
                obj = edit(keys,obj?.convert(),hints,windowTitle)
                    ?.convert()
                    ?:return null

                // return the valid properties file
                return obj
            }
            catch (ex:InputFormatException)
            {
                val options = arrayOf("Continue editing","Discard changes")
                val result = JOptionPane.showOptionDialog(null,ex.message,"Invalid Input Format",JOptionPane.OK_CANCEL_OPTION,JOptionPane.ERROR_MESSAGE,null,options,options[0])
                if (result == JOptionPane.OK_OPTION)
                {
                    continue
                }
                else
                {
                    return null
                }
            }
        }
        while (true)
    }

    class InputFormatException(message:String,cause:Throwable):RuntimeException(message,cause)
}
