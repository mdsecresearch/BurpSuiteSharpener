// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.uimodifiers;

import com.irsdl.burp.generic.BurpTitleAndIcon;
import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.SharpenerBurpExtender;
import com.irsdl.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.burp.sharpener.uimodifiers.toolstabs.ToolsTabStyleHandler;
import com.irsdl.generic.UIHelper;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URI;


public class TopMenuBar extends javax.swing.JMenu {
    private JMenu topMenuForExtension;
    private final SharpenerSharedParameters sharedParameters;
    private final String[] themeNames = {"none", "game", "hacker", "gradient", "mobster", "office"};
    private final Boolean isPrefsRegistered = false;

    public TopMenuBar(SharpenerSharedParameters sharedParameters) {
        super(sharedParameters.extensionName);
        this.sharedParameters = sharedParameters;
        topMenuForExtension = this;
        updateTopMenuBar();
    }

    public void updateTopMenuBar() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new Thread(() -> {
                    removeAll();
                    // Global menu
                    JMenu globalMenu = new JMenu("Global Settings");

                    // Style menu
                    JMenu toolsUniqueStyleMenu = new JMenu("Burp-Tools' Unique Style");
                    JMenuItem enableAll = new JMenuItem(new AbstractAction("Enable All") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            for (BurpUITools.MainTabs tool : BurpUITools.MainTabs.values()) {
                                TopMenuBar.this.sharedParameters.allSettings.saveSettings("isUnique_" + tool.toString(), true);
                                ToolsTabStyleHandler.setToolTabStyle(tool, TopMenuBar.this.sharedParameters);
                            }
                            updateTopMenuBar();
                            //reAddTopMenuBar();
                        }
                    });
                    toolsUniqueStyleMenu.add(enableAll);
                    JMenuItem disableAll = new JMenuItem(new AbstractAction("Disable All") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            for (BurpUITools.MainTabs tool : BurpUITools.MainTabs.values()) {
                                TopMenuBar.this.sharedParameters.allSettings.saveSettings("isUnique_" + tool.toString(), false);
                                ToolsTabStyleHandler.unsetToolTabStyle(tool, TopMenuBar.this.sharedParameters.get_rootTabbedPane());
                            }
                            updateTopMenuBar();
                            //reAddTopMenuBar();
                        }
                    });
                    toolsUniqueStyleMenu.add(disableAll);

                    toolsUniqueStyleMenu.addSeparator();

                    String themeName = sharedParameters.preferences.getSetting("ToolsThemeName");
                    JMenu toolsUniqueStyleThemeMenu = new JMenu("Icons' Theme");
                    ButtonGroup themeGroup = new ButtonGroup();
                    for (String definedThemeName : themeNames) {
                        JRadioButtonMenuItem toolStyleTheme = new JRadioButtonMenuItem(definedThemeName);
                        if (themeName.equalsIgnoreCase(definedThemeName) || (themeName.isEmpty() && definedThemeName.equalsIgnoreCase("none"))) {
                            toolStyleTheme.setSelected(true);
                        }
                        toolStyleTheme.addActionListener((e) -> {
                            String chosenOne = definedThemeName;
                            if (chosenOne.equalsIgnoreCase("none"))
                                chosenOne = "";
                            sharedParameters.allSettings.saveSettings("ToolsThemeName", chosenOne);
                            ToolsTabStyleHandler.resetToolTabStylesFromSettings(sharedParameters);
                        });
                        themeGroup.add(toolStyleTheme);
                        toolsUniqueStyleThemeMenu.add(toolStyleTheme);
                    }

                    JRadioButtonMenuItem toolStyleThemeCustom = new JRadioButtonMenuItem("custom directory");
                    if (themeName.equalsIgnoreCase("custom")) {
                        toolStyleThemeCustom.setSelected(true);
                    }
                    toolStyleThemeCustom.addActionListener((e) -> {
                        String themeCustomPath = sharedParameters.preferences.getSetting("ToolsThemeCustomPath");
                        String customPath = UIHelper.showDirectoryDialog(themeCustomPath, sharedParameters.get_mainFrame());
                        if (!customPath.isEmpty()) {
                            sharedParameters.allSettings.saveSettings("ToolsThemeName", "custom");
                            sharedParameters.allSettings.saveSettings("ToolsThemeCustomPath", customPath);
                        } else {
                            updateTopMenuBar();
                            //reAddTopMenuBar();
                        }
                        ToolsTabStyleHandler.resetToolTabStylesFromSettings(sharedParameters);
                    });
                    themeGroup.add(toolStyleThemeCustom);
                    toolsUniqueStyleThemeMenu.add(toolStyleThemeCustom);
                    toolsUniqueStyleMenu.add(toolsUniqueStyleThemeMenu);

                    toolsUniqueStyleMenu.addSeparator();

                    for (BurpUITools.MainTabs tool : BurpUITools.MainTabs.values()) {
                        if (tool.toString().equalsIgnoreCase("none"))
                            continue;
                        JCheckBoxMenuItem toolStyleOption = new JCheckBoxMenuItem(tool.toString());
                        if ((Boolean) sharedParameters.preferences.getSetting("isUnique_" + tool.toString())) {
                            toolStyleOption.setSelected(true);
                        }
                        toolStyleOption.addActionListener((e) -> {
                            Boolean currentSetting = sharedParameters.preferences.getSetting("isUnique_" + tool.toString());
                            if (currentSetting) {
                                sharedParameters.allSettings.saveSettings("isUnique_" + tool.toString(), false);
                                ToolsTabStyleHandler.unsetToolTabStyle(tool, sharedParameters.get_rootTabbedPane());
                            } else {
                                sharedParameters.allSettings.saveSettings("isUnique_" + tool.toString(), true);
                                ToolsTabStyleHandler.setToolTabStyle(tool, sharedParameters);
                            }
                        });
                        toolsUniqueStyleMenu.add(toolStyleOption);
                    }
                    globalMenu.add(toolsUniqueStyleMenu);

                    // Project menu
                    JMenu projectMenu = new JMenu("Project Settings");

                    // Change title button
                    JMenuItem changeTitle = new JMenuItem(new AbstractAction("Change Title") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            String newTitle = UIHelper.showPlainInputMessage("Change Burp Suite Title String To:", "Change Burp Suite Title", TopMenuBar.this.sharedParameters.get_mainFrame().getTitle(), sharedParameters.get_mainFrame());
                            if (newTitle != null && !newTitle.trim().isEmpty()) {
                                if (!sharedParameters.get_mainFrame().getTitle().equals(newTitle)) {
                                    BurpTitleAndIcon.setTitle(TopMenuBar.this.sharedParameters, newTitle);
                                    TopMenuBar.this.sharedParameters.allSettings.saveSettings("BurpTitle", newTitle);
                                }
                            }
                        }
                    });
                    projectMenu.add(changeTitle);

                    // Change title button
                    JMenuItem changeIcon = new JMenuItem(new AbstractAction("Change Icon") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            String currentIconPath = TopMenuBar.this.sharedParameters.preferences.getSetting("BurpIconCustomPath");
                            FileFilter imageFilter = new FileNameExtensionFilter("Image files", ImageIO.getReaderFileSuffixes());
                            String newIconPath = UIHelper.showFileDialog(currentIconPath, imageFilter, sharedParameters.get_mainFrame());
                            if (newIconPath != null && !newIconPath.trim().isEmpty()) {
                                BurpTitleAndIcon.setIcon(TopMenuBar.this.sharedParameters, newIconPath);
                                TopMenuBar.this.sharedParameters.allSettings.saveSettings("BurpIconCustomPath", newIconPath);
                            }
                        }
                    });
                    projectMenu.add(changeIcon);


                    // Reset title button
                    JMenuItem resetTitle = new JMenuItem(new AbstractAction("Reset Burp Suite Title & Icon") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            int response = UIHelper.askConfirmMessage("Sharpener Extension: Reset Title & Icon", "Are you sure?", new String[]{"Yes", "No"}, sharedParameters.get_mainFrame());
                            if (response == 0) {
                                BurpTitleAndIcon.resetTitleAndIcon(TopMenuBar.this.sharedParameters);
                                TopMenuBar.this.sharedParameters.allSettings.saveSettings("BurpIconCustomPath", "");
                                TopMenuBar.this.sharedParameters.allSettings.saveSettings("BurpTitle", "");
                            }
                        }
                    });
                    projectMenu.add(resetTitle);


                    JCheckBoxMenuItem topMenuScrollableLayout = new JCheckBoxMenuItem("Scrollable Tool Pane");

                    if ((boolean) sharedParameters.preferences.getSetting("isToolTabPaneScrollable")) {
                        topMenuScrollableLayout.setSelected(true);
                    }

                    topMenuScrollableLayout.addActionListener((e) -> {
                        boolean isToolTabPaneScrollable = sharedParameters.preferences.getSetting("isToolTabPaneScrollable");
                        if (isToolTabPaneScrollable) {
                            SwingUtilities.invokeLater(new Runnable() {
                                @Override
                                public void run() {
                                    new Thread(() -> {
                                        sharedParameters.get_rootTabbedPane().setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT);
                                    }).start();
                                }
                            });
                            sharedParameters.allSettings.saveSettings("isToolTabPaneScrollable", false);
                        } else {
                            SwingUtilities.invokeLater(new Runnable() {
                                @Override
                                public void run() {
                                    new Thread(() -> {
                                        sharedParameters.get_rootTabbedPane().setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
                                    }).start();
                                }
                            });
                            sharedParameters.allSettings.saveSettings("isToolTabPaneScrollable", true);
                        }
                    });
                    globalMenu.add(topMenuScrollableLayout);

                    // Debug button
                    JCheckBoxMenuItem debugOption = new JCheckBoxMenuItem("Debug");
                    if (sharedParameters.isDebug) {
                        debugOption.setSelected(true);
                    }
                    debugOption.addActionListener((e) -> {
                        if (sharedParameters.isDebug) {
                            sharedParameters.isDebug = false;
                            sharedParameters.allSettings.saveSettings("isDebug", false);
                        } else {
                            sharedParameters.isDebug = true;
                            sharedParameters.allSettings.saveSettings("isDebug", true);
                        }
                    });
                    globalMenu.add(debugOption);

                    add(projectMenu);
                    add(globalMenu);
                    addSeparator();

                    JMenuItem reloadAllSettings = new JMenuItem(new AbstractAction("Reload Extension") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            new Thread(new Runnable() {
                                @Override
                                public void run() {
                                    ToolsTabStyleHandler.resetToolTabStylesFromSettings(sharedParameters);
                                    //sharedParameters.allSettings.subTabSettings.unsetSubTabsStyle();
                                    SharpenerBurpExtender sharpenerBurpExtender = (SharpenerBurpExtender) sharedParameters.burpExtender;
                                    sharpenerBurpExtender.load(true);

                                }
                            }).start();
                        }
                    });
                    add(reloadAllSettings);

                    JMenuItem resetAllSettings = new JMenuItem(new AbstractAction("Remove All Settings & Unload") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            int response = UIHelper.askConfirmMessage("Sharpener Extension: Reset All Settings & Unload", "Are you sure?", new String[]{"Yes", "No"}, sharedParameters.get_mainFrame());
                            if (response == 0) {

                                // A bug in resetting settings in BurpExtenderUtilities should be fixed so we will give it another chance instead of using a workaround
                                // TopMenuBar.this.sharedParameters.resetAllSettings();
                                TopMenuBar.this.sharedParameters.preferences.resetAllSettings();
                                TopMenuBar.this.sharedParameters.callbacks.unloadExtension();
                            }
                        }
                    });

                    add(resetAllSettings);
                    addSeparator();

                    JCheckBoxMenuItem checkForUpdateOption = new JCheckBoxMenuItem("Check for Update on Start");
                    if ((boolean) sharedParameters.preferences.getSetting("checkForUpdate")) {
                        checkForUpdateOption.setSelected(true);
                    }

                    checkForUpdateOption.addActionListener((e) -> {
                        if ((boolean) sharedParameters.preferences.getSetting("checkForUpdate")) {
                            sharedParameters.allSettings.saveSettings("checkForUpdate", false);
                        } else {
                            sharedParameters.allSettings.saveSettings("checkForUpdate", true);
                            SharpenerBurpExtender sharpenerBurpExtender = (SharpenerBurpExtender) sharedParameters.burpExtender;
                            sharpenerBurpExtender.checkForUpdate();
                        }
                    });
                    add(checkForUpdateOption);

                    JMenuItem showProjectPage = new JMenuItem(new AbstractAction("Project Page") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            new Thread(new Runnable() {
                                @Override
                                public void run() {
                                    try {
                                        Desktop.getDesktop().browse(new URI(sharedParameters.extensionURL));
                                    } catch (Exception e) {
                                    }
                                }
                            }).start();
                        }
                    });
                    add(showProjectPage);

                    JMenuItem reportAnIssue = new JMenuItem(new AbstractAction("Report Bug/Feature") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            new Thread(new Runnable() {
                                @Override
                                public void run() {
                                    try {
                                        Desktop.getDesktop().browse(new URI(sharedParameters.extensionIssueTracker));
                                    } catch (Exception e) {
                                    }
                                }
                            }).start();
                        }
                    });
                    add(reportAnIssue);

                    JMenuItem about = new JMenuItem(new AbstractAction("About") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            String aboutMessage = "Burp Suite " + sharedParameters.extensionName + " - version " + sharedParameters.version +
                                    "\nReleased as open source by MDSec - https://www.mdsec.co.uk/\n" +
                                    "Developed by Soroush Dalili (@irsdl)\n" +
                                    "Project link: " + sharedParameters.extensionURL +
                                    "\nReleased under AGPL see LICENSE for more information";
                            UIHelper.showMessage(aboutMessage, sharedParameters.get_mainFrame());
                        }
                    });
                    add(about);
                }).start();
            }
        });
    }

    public void reAddTopMenuBar() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new Thread(() -> {
                    //removeTopMenuBar(); // this has been disabled as invoke later may mean that the menu may be removed after it is being updated!
                    removeTopMenuBarLastResort(sharedParameters, true);
                    sharedParameters.allSettings.toolsTabSettings.loadSettings(); // this is to reflect the changes in the UI
                    topMenuForExtension = new TopMenuBar(sharedParameters);
                    addTopMenuBar();
                }).start();
            }
        });
    }

    public void addTopMenuBar() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new Thread(() -> {
                    try {
                        // adding toolbar
                        JMenuBar menuBar = sharedParameters.get_mainMenuBar();
                        if (topMenuForExtension == null) {
                            topMenuForExtension = new TopMenuBar(sharedParameters);
                        }
                        //menuBar.add(topMenuForExtension, menuBar.getMenuCount() - 1);
                        // to make it bold
                        topMenuForExtension.setFont(topMenuForExtension.getFont().deriveFont(topMenuForExtension.getFont().getStyle() ^ Font.BOLD));
                        menuBar.add(topMenuForExtension, 5); // we are adding this just after menu `Window`
                        //sharedParameters.get_mainFrame().revalidate();
                        //sharedParameters.get_mainMenuBar().repaint();
                        // to set back to plain after a few seconds
                        new java.util.Timer().schedule(
                                new java.util.TimerTask() {
                                    @Override
                                    public void run() {
                                        topMenuForExtension.setFont(topMenuForExtension.getFont().deriveFont(topMenuForExtension.getFont().getStyle() ^ Font.BOLD));
                                    }
                                },
                                2000
                        );
                    } catch (Exception e) {
                        sharedParameters.stderr.println("Error in adding the top menu: " + e.getMessage());
                    }
                }).start();
            }
        });

    }

    public static void removeTopMenuBarLastResort(SharpenerSharedParameters sharedParameters, boolean repaintUI) {
        if (BurpUITools.isMenubarLoaded(sharedParameters.extensionName, sharedParameters.get_mainMenuBar())) {
            // so the menu is there!
            try {
                sharedParameters.printDebugMessages("removing the menu bar the dirty way!");
                BurpUITools.removeMenubarByName(sharedParameters.extensionName, sharedParameters.get_mainMenuBar(), repaintUI);
            } catch (Exception e) {
                sharedParameters.printlnError("Error in removing the top menu the dirty way: " + e.getMessage());
            }
        }
    }

    public void removeTopMenuBar() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new Thread(() -> {
                    try {
                        // removing old toolbar
                        sharedParameters.get_mainMenuBar().remove(topMenuForExtension);
                    } catch (Exception e) {
                        sharedParameters.stderr.println("Error in removing the top menu: " + e.getMessage());
                    }
                    // just in case the above did not work
                    removeTopMenuBarLastResort(sharedParameters, false);

                    sharedParameters.get_mainMenuBar().revalidate();
                    sharedParameters.get_mainMenuBar().repaint();
                }).start();
            }
        });
    }
}
