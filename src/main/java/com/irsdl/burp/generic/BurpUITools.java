// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.generic;

import com.irsdl.generic.UIHelper;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;
import java.util.ArrayList;
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

    public static void switchToMainTab(String tabName, JTabbedPane tabbedPane) {
        for (Component component : tabbedPane.getComponents()) {
            int componentIndex = tabbedPane.indexOfComponent(component);
            if (componentIndex == -1) {
                continue;
            }

            String componentTitle = tabbedPane.getTitleAt(componentIndex);
            if (componentTitle.trim().equalsIgnoreCase(tabName.trim())) {
                tabbedPane.setSelectedIndex(componentIndex);
                break;
            }
        }
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
                new Thread(() -> {
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
                }).start();
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
            JMenuItem detachedTool = (JMenuItem) BurpUITools.getSubMenuComponentFromMain("Window", "Reattach " + tool.toString(), menuBar, JMenuItem.class);
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

    public static void addMouseWheelToJTabbedPane(JTabbedPane jTabbedPane, boolean isLastOneSelectable) {
        // from https://stackoverflow.com/questions/38463047/use-mouse-to-scroll-through-tabs-in-jtabbedpane
        MouseWheelListener mwl = new MouseWheelListener() {
            @Override
            public void mouseWheelMoved(MouseWheelEvent e) {
                if (e.isControlDown()) {
                    JTabbedPane pane = (JTabbedPane) e.getSource();
                    // works with version 2022.1.1 - not tested in the previous versions!
                    Component component = ((JComponent) pane.getTabComponentAt(pane.getSelectedIndex())).getComponent(0);

                    float currentFontSize = component.getFont().getSize();

                    if (e.getWheelRotation() < 0) {
                        //scrolled up
                        if(currentFontSize<=36){
                            component.setFont(component.getFont().deriveFont(currentFontSize+2));

                        }
                    } else {
                        //scrolled down
                        if(currentFontSize>=12) {
                            component.setFont(component.getFont().deriveFont(currentFontSize - 2));
                        }
                    }
                }else{
                    int offset = 0;
                    if (!isLastOneSelectable)
                        offset = 1;

                    JTabbedPane pane = (JTabbedPane) e.getSource();
                    int units = e.getWheelRotation();
                    int oldIndex = pane.getSelectedIndex();
                    int newIndex = oldIndex + units;
                    if (newIndex < 0)
                        pane.setSelectedIndex(0);
                    else if (newIndex >= pane.getTabCount() - offset)
                        pane.setSelectedIndex(pane.getTabCount() - 1 - offset);
                    else
                        pane.setSelectedIndex(newIndex);
                }

            }
        };
        jTabbedPane.addMouseWheelListener(mwl);
    }

    public static void removeMouseWheelFromJTabbedPane(JTabbedPane jTabbedPane, boolean onlyRemoveLast) {
        MouseWheelListener[] mwlArr = jTabbedPane.getMouseWheelListeners();
        for (int i = mwlArr.length - 1; i >= 0; i--) {
            jTabbedPane.removeMouseWheelListener(mwlArr[i]);
            if (onlyRemoveLast) {
                break;
            }
        }
    }
}
