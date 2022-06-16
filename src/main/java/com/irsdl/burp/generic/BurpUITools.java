// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.generic;

import javax.swing.*;
import java.awt.*;
import java.util.Set;

public class BurpUITools {
    public enum MainTabs {
        None("None"),
        Dashboard("Dashboard"),
        Target("Target"),
        Proxy("Proxy"),
        Intruder("Intruder"),
        Sequencer("Sequencer"),
        Repeater("Repeater"),
        Decoder("Decoder"),
        Comparer("Comparer"),
        Extender("Extender"),
        ProjectOptions("Project options"),
        UserOptions("User options"),
        Logger("Logger"),
        //HackVertor("Hackvertor"),
        ;
        private final String text;

        /**
         * @param text
         */
        MainTabs(final String text) {
            this.text = text;
        }

        /* (non-Javadoc)
         * @see java.lang.Enum#toString()
         */
        @Override
        public String toString() {
            return text;
        }
    }

    public static MainTabs getMainTabsObjFromString(String tabTitleName) {
        MainTabs result = MainTabs.None;
        if (tabTitleName != null) {
            for (MainTabs tab : BurpUITools.MainTabs.values()) {
                if (tab.toString().equalsIgnoreCase(tabTitleName.trim())) {
                    result = tab;
                    break;
                }
            }
        }
        return result;
    }

    public static boolean isDarkMode(Component component) {
        boolean result = false;
        if (component.getBackground().getBlue() < 128) {
            result = true;
        }
        return result;
    }

    public static boolean switchToMainTab(String tabName, JTabbedPane tabbedPane) {
        boolean result = false;
        for (Component component : tabbedPane.getComponents()) {
            int componentIndex = tabbedPane.indexOfComponent(component);
            if (componentIndex == -1) {
                continue;
            }

            String componentTitle = tabbedPane.getTitleAt(componentIndex);
            if (componentTitle.trim().equalsIgnoreCase(tabName.trim())) {
                tabbedPane.setSelectedIndex(componentIndex);
                result = true;
                break;
            }
        }

        return result;
    }

    public static Boolean isStringInMainTabs(String tabTitleName) {
        boolean result = true;
        try {
            MainTabs.valueOf(tabTitleName);
        } catch (Exception e) {
            result = false;
        }
        return result;
    }

    // This is case insensitive to prevent confusion
    public static Boolean isMenubarLoaded(String toolbarName, JMenuBar menuBar) {
        Boolean result = false;
        for (int i = 0; i < menuBar.getMenuCount(); i++) {
            JMenuItem item = menuBar.getMenu(i);
            if (item.getText().trim().equalsIgnoreCase(toolbarName.trim())) {
                result = true;
                break;
            }
        }
        return result;
    }

    // This is case insensitive to prevent confusion
    public static void removeMenubarByName(String toolbarName, JMenuBar menuBar, boolean repaintUI) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {

                for (int i = 0; i < menuBar.getMenuCount(); i++) {
                    JMenuItem item = menuBar.getMenu(i);
                    if (item.getText().trim().equalsIgnoreCase(toolbarName.trim())) {
                        menuBar.remove(i);
                        // break; // we may have more than one menu so this line needs to be commented
                    }
                }

                if (repaintUI) {
                    menuBar.revalidate();
                    menuBar.repaint();
                }

            }
        });
    }

    // This is case insensitive to prevent confusion
    public static JMenuItem getMenuItem(String toolbarName, JMenuBar menuBar) {
        JMenuItem result = null;
        for (int i = 0; i < menuBar.getMenuCount(); i++) {
            JMenuItem item = menuBar.getMenu(i);
            if (item.getText().trim().equalsIgnoreCase(toolbarName.trim())) {
                result = item;
                break;
            }
        }
        return result;
    }

    // This is case insensitive to prevent confusion
    public static MenuElement getSubMenuComponentFromMain(String toolbarName, String subItemName, JMenuBar menuBar, Class componentType) {
        MenuElement result = null;
        JMenuItem mainMenuItem = getMenuItem(toolbarName, menuBar);
        if (mainMenuItem != null) {
            for (int i = 0; i < mainMenuItem.getSubElements()[0].getSubElements().length - 1; i++) {
                MenuElement item = mainMenuItem.getSubElements()[0].getSubElements()[i];
                if (item instanceof JMenuItem) {
                    JMenuItem finalObj = (JMenuItem) item;
                    if (finalObj.getText().equalsIgnoreCase(subItemName)) {
                        result = finalObj;
                        break;
                    }
                } else if (item instanceof JMenu) {
                    JMenu finalObj = (JMenu) item;
                    if (finalObj.getText().equalsIgnoreCase(subItemName)) {
                        result = finalObj;
                        break;
                    }
                } else if (item instanceof JCheckBoxMenuItem) {
                    JCheckBoxMenuItem finalObj = (JCheckBoxMenuItem) item;
                    if (finalObj.getText().equalsIgnoreCase(subItemName)) {
                        result = finalObj;
                        break;
                    }
                }
            }
        }
        return result;
    }

    public static boolean reattachTools(Set<BurpUITools.MainTabs> toolName, JMenuBar menuBar) {
        boolean result = false;
        for (BurpUITools.MainTabs tool : toolName) {
            JMenuItem detachedTool = (JMenuItem) BurpUITools.getSubMenuComponentFromMain("Window", "Reattach " + tool, menuBar, JMenuItem.class);
            if (detachedTool != null) {
                detachedTool.doClick();
                result = true;
            }
        }
        return result;
    }

    // This is case insensitive to prevent confusion
    public static Boolean isTabLoaded(String tabName, JTabbedPane tabbedPane) {
        Boolean result = false;
        for (Component component : tabbedPane.getComponents()) {
            int componentIndex = tabbedPane.indexOfComponent(component);
            if (componentIndex == -1) {
                continue;
            }

            String componentTitle = tabbedPane.getTitleAt(componentIndex);
            if (componentTitle.trim().equalsIgnoreCase(tabName.trim())) {
                result = true;
                break;
            }
        }
        return result;
    }
}
