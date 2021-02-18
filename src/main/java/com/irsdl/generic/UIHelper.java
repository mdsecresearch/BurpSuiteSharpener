// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.generic;

import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import java.awt.*;
import java.io.File;

public class UIHelper {

    // Show a message to the user
    public static void showMessage(final String strMsg, Component parentcmp) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                JOptionPane.showMessageDialog(parentcmp, strMsg);
            }
        }).start();

    }

    // Show a message to the user
    public static void showWarningMessage(final String strMsg, Component parentcmp) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                JOptionPane.showMessageDialog(parentcmp, strMsg, "Warning", JOptionPane.WARNING_MESSAGE);
            }
        }).start();
    }

    // Show a message to the user
    public static String showPlainInputMessage(final String strMessage, final String strTitle, final String defaultValue, Component parentcmp) {
        String output = (String) JOptionPane.showInputDialog(parentcmp,
                strMessage, strTitle, JOptionPane.PLAIN_MESSAGE, null, null, defaultValue);
        if (output == null) {
            output = defaultValue;
        }
        return output;
    }

    // Common method to ask a multiple question
    public static Integer askConfirmMessage(final String strTitle, final String strQuestion, String[] msgOptions, Component parentcmp) {
        final Object[] options = msgOptions;
        final int[] choice = new int[1];
        choice[0] = 0;
        choice[0] = JOptionPane.showOptionDialog(parentcmp,
                strQuestion,
                strTitle,
                JOptionPane.YES_NO_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                options,
                options[0]);
        return choice[0];
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
        if(isSave){
            returnVal = _fileChooser.showSaveDialog(parentcmp);
        }else{
            returnVal = _fileChooser.showOpenDialog(parentcmp);
        }

        if (returnVal == JFileChooser.APPROVE_OPTION) {
            filePath = _fileChooser.getSelectedFile().getAbsolutePath();
        }
        return filePath;
    }

}
