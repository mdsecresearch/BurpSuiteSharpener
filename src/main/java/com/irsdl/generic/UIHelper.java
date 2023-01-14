// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.generic;

import com.irsdl.burp.generic.BurpTitleAndIcon;

import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;

public class UIHelper {

    // Show a message to the user
    public static void showMessage(final String strMsg, final String strTitle, Component parentcmp) {
        new Thread(() -> JOptionPane.showMessageDialog(parentcmp, strMsg, strTitle, JOptionPane.INFORMATION_MESSAGE)).start();

    }

    // Show a message to the user
    public static void showWarningMessage(final String strMsg, Component parentcmp) {
        new Thread(() -> JOptionPane.showMessageDialog(parentcmp, strMsg, "Warning", JOptionPane.WARNING_MESSAGE)).start();
    }

    // Show a message to the user
    public static String showPlainInputMessage(final String strMessage, final String strTitle, final String defaultValue, Component parentcmp) {
        String output = (String) JOptionPane.showInputDialog(parentcmp,
                strMessage, strTitle, JOptionPane.PLAIN_MESSAGE, null, null, defaultValue);
        if (output == null) {
            output = defaultValue;
        }

        if(output == null)
            output = "";

        return output;
    }

    // Common method to ask a multiline question
    public static String[] showPlainInputMessages(final String strMessages[], final String strTitle, final String defaultValues[], Component parentcmp) {
        String[] output = new String[strMessages.length];
        java.util.List<Object> strMessagesObjectList = new ArrayList<>();

        for (int i = 0; i < strMessages.length; i++) {
            String defaultValue = "";
            if (defaultValues.length > i)
                defaultValue = defaultValues[i];
            strMessagesObjectList.add(strMessages[i]);
            strMessagesObjectList.add(new JTextField(defaultValue));
        }

        int option = JOptionPane.showConfirmDialog(parentcmp, strMessagesObjectList.toArray(), strTitle, JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.OK_OPTION) {
            for (int i = 0; i < strMessages.length; i++) {
                output[i] = ((JTextField) strMessagesObjectList.get(i * 2 + 1)).getText();
            }
        }
        if(output == null)
            output = new String[strMessages.length];
        return output;
    }

    // Common method to ask a multiple question
    public static Integer askConfirmMessage(final String strTitle, final String strQuestion, String[] msgOptions, Component parentcmp) {
        Integer output = JOptionPane.showOptionDialog(parentcmp,
                strQuestion,
                strTitle,
                JOptionPane.YES_NO_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                msgOptions,
                msgOptions[0]);
        if(output == null)
            output = -1;
        return output;
    }

    // to update the JCheckbox background colour after using the customizeUiComponent() method
    public static void updateJCheckBoxBackground(Container c) {
        Component[] components = c.getComponents();
        for (Component com : components) {
            if (com instanceof JCheckBox) {
                com.setBackground(c.getBackground());
            } else if (com instanceof Container) {
                updateJCheckBoxBackground((Container) com);
            }
        }
    }

    // Show directory dialog and return the path
    public static String showDirectoryDialog(final String initialPath, Component parentcmp) {
        return showFileDialog(initialPath, true, null, parentcmp, false);
    }

    // Show directory dialog and return the path
    public static String showDirectorySaveDialog(final String initialPath, Component parentcmp) {
        return showFileDialog(initialPath, true, null, parentcmp, true);
    }

    // Show file dialog and return the file path
    public static String showFileDialog(final String initialPath, FileFilter fileFilter, Component parentcmp) {
        return showFileDialog(initialPath, false, fileFilter, parentcmp, false);
    }

    // Show file chooser
    public static String showFileDialog(final String initialPath, final boolean dirOnly, FileFilter fileFilter, Component parentcmp, boolean isSave) {
        String filePath = "";
        JFileChooser _fileChooser = new JFileChooser();
        if (dirOnly)
            _fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);

        if (fileFilter != null)
            _fileChooser.setFileFilter(fileFilter);

        if (!initialPath.trim().isEmpty()) {
            File file = new File(initialPath);
            _fileChooser.setCurrentDirectory(file);
        }

        int returnVal;
        if (isSave) {
            returnVal = _fileChooser.showSaveDialog(parentcmp);
        } else {
            returnVal = _fileChooser.showOpenDialog(parentcmp);
        }

        if (returnVal == JFileChooser.APPROVE_OPTION) {
            filePath = _fileChooser.getSelectedFile().getAbsolutePath();
        }

        if(filePath == null)
            filePath = "";

        return filePath;
    }

    public static boolean isFrameOutOffScreen(JFrame jframe, double offScreenMargin){
        boolean result = false;
        try{
            if(offScreenMargin > 1 || offScreenMargin < 0)
                offScreenMargin = 0;

            Rectangle bounds = new Rectangle(0, 0, 0, 0);
            GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
            GraphicsDevice lstGDs[] = ge.getScreenDevices();
            for (GraphicsDevice gd : lstGDs) {
                bounds.add(gd.getDefaultConfiguration().getBounds());
            }

            Rectangle frameBounds = jframe.getBounds();
            double widthOffset = offScreenMargin * frameBounds.getWidth();
            double heightOffset = offScreenMargin * frameBounds.getHeight();
            Rectangle boundsWithThreshold = new Rectangle((int)(bounds.getX() - widthOffset),
                    (int)(bounds.getY() - heightOffset),
                    (int)(bounds.getWidth() + 2 * widthOffset),
                    (int)(bounds.getHeight() + 2 * heightOffset)
            );

            result = !boundsWithThreshold.contains(frameBounds);

        }catch(Exception e){
            result = false;
            System.err.println("Error in isFrameOutOffScreen, it has been ignored");
        }
        return result;
    }

    public static void moveFrameToCenter(JFrame jframe){
        try{
            Dimension dim = Toolkit.getDefaultToolkit().getScreenSize();
            jframe.setLocation(dim.width/2-jframe.getSize().width/2, dim.height/2-jframe.getSize().height/2);
        }catch(Exception e){
            System.err.println("Error in moveFrameToCenter, it has been ignored");
        }

    }

}
