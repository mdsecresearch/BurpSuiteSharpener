// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.uiModifiers.toolsTabs;

import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.generic.ImageHelper;

import javax.swing.*;
import java.awt.*;


public class MainToolsTabStyleHandler {
    public static void setToolTabStyle(SharpenerSharedParameters sharedParameters, BurpUITools.MainTabs toolName) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                sharedParameters.printDebugMessage("setToolTabStyle for " + toolName);
                String themeName = sharedParameters.preferences.safeGetStringSetting("ToolsThemeName");
                String themeCustomPath = sharedParameters.preferences.safeGetStringSetting("ToolsThemeCustomPath");
                String iconSizeStr = sharedParameters.preferences.safeGetStringSetting("ToolsIconSize");
                int iconSize = Integer.parseInt(iconSizeStr, 32);

                JTabbedPane tabbedPane = sharedParameters.get_rootTabbedPane();
                for (Component component : tabbedPane.getComponents()) {
                    int componentIndex = tabbedPane.indexOfComponent(component);
                    if (componentIndex == -1) {
                        continue;
                    }

                    String componentTitle = tabbedPane.getTitleAt(componentIndex);
                    if (componentTitle.equalsIgnoreCase(toolName.toString())) {
                        JComponent tabComponent = (JComponent) tabbedPane.getTabComponentAt(componentIndex);
                        if (tabComponent.getComponent(0) instanceof JTextField) {

                            JTextField jTextField = (JTextField) tabComponent.getComponent(0);
                            jTextField.setFont(jTextField.getFont().deriveFont(Font.BOLD));
                            jTextField.setOpaque(false);
                            jTextField.setBorder(javax.swing.BorderFactory.createEmptyBorder());
                            try {
                                Image myImg;
                                if (!themeName.equalsIgnoreCase("custom")) {
                                    myImg = ImageHelper.scaleImageToWidth(ImageHelper.loadImageResource(sharedParameters.extensionClass, "/themes/" + themeName + "/" + toolName.toString() + ".png"), iconSize);
                                } else {
                                    // custom path!
                                    myImg = ImageHelper.scaleImageToWidth(ImageHelper.loadImageFile(themeCustomPath + "/" + toolName.toString() + ".png"), iconSize);
                                    if (myImg == null) {
                                        sharedParameters.printlnError("'" + themeCustomPath + "/" + toolName.toString() + ".png' could not be loaded or did not exist.");
                                    }
                                }
                                JLabel jLabel;
                                if (myImg != null) {
                                    ImageIcon imgIcon = new ImageIcon(myImg);
                                    jLabel = new JLabel(imgIcon);
                                } else {
                                    jLabel = new JLabel();
                                }
                                jLabel.setOpaque(false);
                                jLabel.setBorder(javax.swing.BorderFactory.createEmptyBorder());

                                //tabComponent.setLayout(new GridLayout(1, 2));
                                tabComponent.setLayout(new FlowLayout(FlowLayout.CENTER));
                                tabComponent.setSize(jTextField.getWidth() + jLabel.getWidth(), jLabel.getHeight());
                                tabComponent.remove(0);
                                tabComponent.add(jLabel);
                                tabComponent.add(jTextField);
                            } catch (Exception e) {
                                e.printStackTrace(sharedParameters.stderr);
                            }

                            tabComponent.revalidate();
                            //tabComponent.repaint();

                        }
                        break;
                    }
                }
            }
        });


    }

    private static void setToolTabStylesFromSettings(SharpenerSharedParameters sharedParameters) {
        // Loading global settings
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                sharedParameters.printDebugMessage("setToolTabStylesFromSettings");
                if (sharedParameters.preferences.safeGetBooleanSetting("isToolTabPaneScrollable")) {
                    sharedParameters.get_rootTabbedPane().setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
                }

                for (BurpUITools.MainTabs tool : BurpUITools.MainTabs.values()) {
                    if (sharedParameters.preferences.safeGetBooleanSetting("isUnique_" + tool)) {
                        MainToolsTabStyleHandler.setToolTabStyle(sharedParameters, tool);
                    }
                }
            }
        });
    }

    public static void resetToolTabStylesFromSettings(SharpenerSharedParameters sharedParameters) {
        sharedParameters.printDebugMessage("resetToolTabStylesFromSettings");
        //unsetAllToolTabStyles(sharedParameters);
        //setToolTabStylesFromSettings(sharedParameters);
        // instead of two commented lines above, we want to reset it more smoothly
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                sharedParameters.printDebugMessage("setToolTabStylesFromSettings");
                if (sharedParameters.preferences.safeGetBooleanSetting("isToolTabPaneScrollable")) {
                    sharedParameters.get_rootTabbedPane().setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
                } else {
                    sharedParameters.get_rootTabbedPane().setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT);
                }

                for (BurpUITools.MainTabs tool : BurpUITools.MainTabs.values()) {
                    if (sharedParameters.preferences.safeGetBooleanSetting("isUnique_" + tool)) {
                        MainToolsTabStyleHandler.unsetToolTabStyle(sharedParameters, tool);
                        MainToolsTabStyleHandler.setToolTabStyle(sharedParameters, tool);
                    }
                }
            }
        });
    }

    public static void unsetAllToolTabStyles(SharpenerSharedParameters sharedParameters) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                sharedParameters.printDebugMessage("unsetAllToolTabStyles");
                if (sharedParameters.preferences.safeGetBooleanSetting("isToolTabPaneScrollable")) {
                    sharedParameters.get_rootTabbedPane().setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT);
                }
                for (BurpUITools.MainTabs tool : BurpUITools.MainTabs.values()) {
                    //new Thread(() -> ToolsTabStyleHandler.unsetToolTabStyle(tool, tabbedPane)).start();
                    MainToolsTabStyleHandler.unsetToolTabStyle(sharedParameters, tool);
                }
            }
        });
    }

    public static void unsetToolTabStyle(SharpenerSharedParameters sharedParameters, BurpUITools.MainTabs toolName) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                JTabbedPane tabbedPane = sharedParameters.get_rootTabbedPane();
                for (Component component : tabbedPane.getComponents()) {
                    int componentIndex = tabbedPane.indexOfComponent(component);
                    if (componentIndex == -1) {
                        continue;
                    }

                    String componentTitle = tabbedPane.getTitleAt(componentIndex);
                    if (componentTitle == null)
                        continue;

                    if (componentTitle.equalsIgnoreCase(toolName.toString())) {
                        JComponent tabComponent = (JComponent) tabbedPane.getTabComponentAt(componentIndex);
                        if (tabComponent.getComponent(0) instanceof JLabel) {
                            tabComponent.remove(0);
                            JTextField jTextField = (JTextField) tabComponent.getComponent(0);
                            jTextField.setFont(jTextField.getFont().deriveFont(Font.PLAIN));
                            jTextField.setOpaque(false);
                            jTextField.setBorder(javax.swing.BorderFactory.createEmptyBorder());
                            tabComponent.setSize(jTextField.getWidth(), jTextField.getHeight());
                            //tabComponent.revalidate();
                            //tabComponent.repaint();
                        }
                        break;
                    }
                }
            }
        });
    }
}
