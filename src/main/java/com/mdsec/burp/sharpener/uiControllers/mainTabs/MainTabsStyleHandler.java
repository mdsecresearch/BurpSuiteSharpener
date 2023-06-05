// Burp Suite Extension Name: Sharpener
// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)
// Released initially as open source by MDSec - https://www.mdsec.co.uk
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener

package com.mdsec.burp.sharpener.uiControllers.mainTabs;

import com.irsdl.burp.generic.BurpUITools;
import com.mdsec.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.generic.ImageHelper;

import javax.swing.*;
import java.awt.*;


public class MainTabsStyleHandler {
    public static void setMainTabsStyle(SharpenerSharedParameters sharedParameters, BurpUITools.MainTabs toolName) {
        SwingUtilities.invokeLater(() -> {

            sharedParameters.printDebugMessage("setToolTabStyle for " + toolName);
            String themeName = sharedParameters.preferences.safeGetStringSetting("ToolsThemeName");
            String themeCustomPath = sharedParameters.preferences.safeGetStringSetting("ToolsThemeCustomPath");
            String iconSizeStr = sharedParameters.preferences.safeGetStringSetting("ToolsIconSize");
            int iconSize = Integer.parseInt(iconSizeStr, 16);

            JTabbedPane tabbedPane = sharedParameters.get_rootTabbedPaneUsingMontoya();
            for (Component component : tabbedPane.getComponents()) {
                int componentIndex = tabbedPane.indexOfComponent(component);
                if (componentIndex == -1) {
                    continue;
                }

                String componentTitle = tabbedPane.getTitleAt(componentIndex);
                if (componentTitle.equalsIgnoreCase(toolName.toString())) {
                    JComponent tabComponent = (JComponent) tabbedPane.getTabComponentAt(componentIndex);
                    if (tabComponent.getComponent(0) instanceof JTextField jTextField) {

                        jTextField.setFont(jTextField.getFont().deriveFont(Font.BOLD));
                        jTextField.setOpaque(false);
                        jTextField.setBorder(BorderFactory.createEmptyBorder());
                        try {
                            Image myImg;
                            if (!themeName.equalsIgnoreCase("custom")) {
                                myImg = ImageHelper.scaleImageToWidth(ImageHelper.loadImageResource(sharedParameters.extensionClass, "/themes/" + themeName + "/" + toolName + ".png"), iconSize);
                                if(myImg==null){
                                    // is this an extension?
                                    myImg = ImageHelper.scaleImageToWidth(ImageHelper.loadImageResource(sharedParameters.extensionClass, "/themes/extensions/" + toolName + ".png"), iconSize);
                                }
                            } else {
                                // custom path!
                                myImg = ImageHelper.scaleImageToWidth(ImageHelper.loadImageFile(themeCustomPath + "/" + toolName + ".png"), iconSize);
                                if (myImg == null) {
                                    sharedParameters.printlnError("'" + themeCustomPath + "/" + toolName + ".png' could not be loaded or did not exist.");
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
                            jLabel.setBorder(BorderFactory.createEmptyBorder());

                            tabComponent.setLayout(new FlowLayout(FlowLayout.CENTER));
                            tabComponent.setSize(jTextField.getWidth() + jLabel.getWidth(), jLabel.getHeight());
                            tabComponent.remove(0);
                            tabComponent.add(jLabel);
                            tabComponent.add(jTextField);
                        } catch (Exception e) {
                            e.printStackTrace(sharedParameters.stderr);
                        }

                    }
                    break;
                }
            }
            tabbedPane.revalidate();
            tabbedPane.repaint();
        });


    }

    public static void resetMainTabsStylesFromSettings(SharpenerSharedParameters sharedParameters) {
        sharedParameters.printDebugMessage("resetToolTabStylesFromSettings");
        //unsetAllToolTabStyles(sharedParameters);
        //setToolTabStylesFromSettings(sharedParameters);
        // instead of two commented lines above, we want to reset it more smoothly
        SwingUtilities.invokeLater(() -> {

            sharedParameters.printDebugMessage("setToolTabStylesFromSettings");
            if (sharedParameters.preferences.safeGetBooleanSetting("isToolTabPaneScrollable")) {
                sharedParameters.get_rootTabbedPaneUsingMontoya().setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
            } else {
                sharedParameters.get_rootTabbedPaneUsingMontoya().setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT);
            }

            for (BurpUITools.MainTabs tool : BurpUITools.MainTabs.values()) {
                if (sharedParameters.preferences.safeGetBooleanSetting("isUnique_" + tool)) {
                    MainTabsStyleHandler.unsetMainTabsStyle(sharedParameters, tool);
                    MainTabsStyleHandler.setMainTabsStyle(sharedParameters, tool);
                }
            }
        });
    }

    public static void unsetAllMainTabsStyles(SharpenerSharedParameters sharedParameters) {
        SwingUtilities.invokeLater(() -> {

            sharedParameters.printDebugMessage("unsetAllToolTabStyles");
            if (!sharedParameters.isSubTabScrollSupportedByDefault) {
                if (sharedParameters.preferences.safeGetBooleanSetting("isToolTabPaneScrollable")) {
                    sharedParameters.get_rootTabbedPaneUsingMontoya().setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT);
                }
            }

            for (BurpUITools.MainTabs tool : BurpUITools.MainTabs.values()) {
                MainTabsStyleHandler.unsetMainTabsStyle(sharedParameters, tool);
            }

        });
    }

    public static void unsetMainTabsStyle(SharpenerSharedParameters sharedParameters, BurpUITools.MainTabs toolName) {
        SwingUtilities.invokeLater(() -> {

            JTabbedPane tabbedPane = sharedParameters.get_rootTabbedPaneUsingMontoya();
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
                        jTextField.setBorder(BorderFactory.createEmptyBorder());
                        tabComponent.setSize(jTextField.getWidth(), jTextField.getHeight());
                    }
                    break;
                }
            }

        });
    }
}
