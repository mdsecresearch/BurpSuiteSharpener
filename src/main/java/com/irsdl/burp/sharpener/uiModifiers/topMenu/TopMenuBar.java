// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.uiModifiers.topMenu;

import com.irsdl.burp.generic.BurpTitleAndIcon;
import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.SharpenerBurpExtender;
import com.irsdl.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.burp.sharpener.uiModifiers.toolsTabs.MainToolsTabStyleHandler;
import com.irsdl.generic.ImageHelper;
import com.irsdl.generic.UIHelper;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.Timer;


public class TopMenuBar extends javax.swing.JMenu {
    private JMenu topMenuForExtension;
    private final SharpenerSharedParameters sharedParameters;
    private final String[] themeNames = {"none", "halloween", "game", "hacker", "gradient", "mobster", "office"};
    private final String[] iconSizes = {"48", "32", "24", "20", "16", "14", "12", "10" , "8", "6"};
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

                    // Project menu
                    JMenu projectMenu = new JMenu("Project Settings");

                    // Change title button
                    JMenuItem changeTitle = new JMenuItem(new AbstractAction("Change Title") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            String newTitle = UIHelper.showPlainInputMessage("Change Burp Suite Title String To:", "Change Burp Suite Title", sharedParameters.get_mainFrame().getTitle(), sharedParameters.get_mainFrame());
                            if (newTitle != null && !newTitle.trim().isEmpty()) {
                                if (!sharedParameters.get_mainFrame().getTitle().equals(newTitle)) {
                                    BurpTitleAndIcon.setTitle(sharedParameters, newTitle);
                                    sharedParameters.allSettings.saveSettings("BurpTitle", newTitle);
                                }
                            }
                        }
                    });
                    projectMenu.add(changeTitle);

                    // Change title button
                    String burpResourceIconName = sharedParameters.preferences.getSetting("BurpResourceIconName");
                    Resource[] resourceIcons = new Resource[]{};

                    try {
                        PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver(sharedParameters.extensionClass.getClassLoader());
                        resourceIcons = resolver.getResources("classpath:icons/*.*");

                    } catch (IOException e) {
                        sharedParameters.printDebugMessage("No icon was found in resources");
                    }

                    JMenu changeBurpIcon = new JMenu("Change Burp Suite Icon");

                    ButtonGroup burpIconGroup = new ButtonGroup();
                    for(Resource resourceIcon: resourceIcons){
                        String resourcePath = "/icons/"+resourceIcon.getFilename();
                        JRadioButtonMenuItem burpIconImage = new JRadioButtonMenuItem(resourceIcon.getFilename().replaceAll("\\..*$",""));
                        burpIconImage.setIcon(new ImageIcon(ImageHelper.scaleImageToWidth(ImageHelper.loadImageResource(sharedParameters.extensionClass, resourcePath), 16)));
                        if (resourceIcon.getFilename().equalsIgnoreCase(burpResourceIconName)) {
                            burpIconImage.setSelected(true);
                        }
                        burpIconImage.addActionListener((e) -> {
                            BurpTitleAndIcon.setIcon(sharedParameters, resourcePath, 48, true);
                            sharedParameters.allSettings.saveSettings("BurpResourceIconName", resourcePath);
                            sharedParameters.allSettings.saveSettings("BurpIconCustomPath", "");
                        });
                        burpIconGroup.add(burpIconImage);
                        changeBurpIcon.add(burpIconImage);
                    }

                    JRadioButtonMenuItem burpIconImage = new JRadioButtonMenuItem("Custom");
                    if(!((String) sharedParameters.preferences.getSetting("BurpIconCustomPath")).isBlank()){
                        burpIconImage.setSelected(true);
                    }

                    burpIconImage.addActionListener(new AbstractAction() {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            String lastIconPath = sharedParameters.preferences.getSetting("LastBurpIconCustomPath");
                            FileFilter imageFilter = new FileNameExtensionFilter("Image files", ImageIO.getReaderFileSuffixes());
                            String newIconPath = UIHelper.showFileDialog(lastIconPath, imageFilter, sharedParameters.get_mainFrame());
                            if (newIconPath != null && !newIconPath.trim().isEmpty()) {
                                BurpTitleAndIcon.setIcon(sharedParameters, newIconPath, 48, false);
                                sharedParameters.allSettings.saveSettings("BurpResourceIconName", "");
                                sharedParameters.allSettings.saveSettings("BurpIconCustomPath", newIconPath);
                                sharedParameters.allSettings.saveSettings("LastBurpIconCustomPath", newIconPath);
                            }
                        }
                    });
                    burpIconGroup.add(burpIconImage);
                    changeBurpIcon.add(burpIconImage);

                    projectMenu.add(changeBurpIcon);


                    // Reset title button
                    JMenuItem resetTitle = new JMenuItem(new AbstractAction("Reset Burp Suite Title") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            int response = UIHelper.askConfirmMessage("Sharpener Extension: Reset Title", "Are you sure?", new String[]{"Yes", "No"}, sharedParameters.get_mainFrame());
                            if (response == 0) {
                                BurpTitleAndIcon.resetTitle(sharedParameters);
                                sharedParameters.allSettings.saveSettings("BurpTitle", "");
                            }
                        }
                    });
                    projectMenu.add(resetTitle);

                    // Reset icon button
                    JMenuItem resetIcon = new JMenuItem(new AbstractAction("Reset Burp Suite Icon") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            int response = UIHelper.askConfirmMessage("Sharpener Extension: Reset Icon", "Are you sure?", new String[]{"Yes", "No"}, sharedParameters.get_mainFrame());
                            if (response == 0) {
                                BurpTitleAndIcon.resetIcon(sharedParameters);
                                sharedParameters.allSettings.saveSettings("BurpIconCustomPath", "");
                            }
                        }
                    });
                    projectMenu.add(resetIcon);
                    add(projectMenu);

                    // Global menu
                    JMenu globalMenu = new JMenu("Global Settings");

                    // Style menu
                    JMenu toolsUniqueStyleMenu = new JMenu("Burp-Tools' Unique Style");
                    JMenuItem enableAll = new JMenuItem(new AbstractAction("Enable All") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            for (BurpUITools.MainTabs tool : BurpUITools.MainTabs.values()) {
                                sharedParameters.allSettings.saveSettings("isUnique_" + tool, true);
                                MainToolsTabStyleHandler.setToolTabStyle(sharedParameters, tool);
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
                                sharedParameters.allSettings.saveSettings("isUnique_" + tool, false);
                                MainToolsTabStyleHandler.unsetToolTabStyle(sharedParameters, tool);
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
                            MainToolsTabStyleHandler.resetToolTabStylesFromSettings(sharedParameters);
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
                        MainToolsTabStyleHandler.resetToolTabStylesFromSettings(sharedParameters);
                    });
                    themeGroup.add(toolStyleThemeCustom);
                    toolsUniqueStyleThemeMenu.add(toolStyleThemeCustom);
                    toolsUniqueStyleMenu.add(toolsUniqueStyleThemeMenu);

                    String iconSize = sharedParameters.preferences.getSetting("ToolsIconSize");
                    JMenu toolsUniqueStyleIconSizeMenu = new JMenu("Icons' Size");
                    ButtonGroup iconSizeGroup = new ButtonGroup();
                    for (String definedIconSize: iconSizes) {
                        JRadioButtonMenuItem toolIconSize = new JRadioButtonMenuItem(definedIconSize);
                        if (iconSize.equals(definedIconSize)) {
                            toolIconSize.setSelected(true);
                        }
                        toolIconSize.addActionListener((e) -> {
                            String chosenOne = definedIconSize;
                            sharedParameters.allSettings.saveSettings("ToolsIconSize", chosenOne);
                            MainToolsTabStyleHandler.resetToolTabStylesFromSettings(sharedParameters);
                        });
                        iconSizeGroup.add(toolIconSize);
                        toolsUniqueStyleIconSizeMenu.add(toolIconSize);
                    }
                    toolsUniqueStyleMenu.add(toolsUniqueStyleIconSizeMenu);

                    toolsUniqueStyleMenu.addSeparator();

                    for (BurpUITools.MainTabs tool : BurpUITools.MainTabs.values()) {
                        if (tool.toString().equalsIgnoreCase("none"))
                            continue;
                        JCheckBoxMenuItem toolStyleOption = new JCheckBoxMenuItem(tool.toString());
                        if ((Boolean) sharedParameters.preferences.getSetting("isUnique_" + tool)) {
                            toolStyleOption.setSelected(true);
                        }
                        toolStyleOption.addActionListener((e) -> {
                            Boolean currentSetting = sharedParameters.preferences.getSetting("isUnique_" + tool);
                            if (currentSetting) {
                                sharedParameters.allSettings.saveSettings("isUnique_" + tool, false);
                                MainToolsTabStyleHandler.unsetToolTabStyle(sharedParameters, tool);
                            } else {
                                sharedParameters.allSettings.saveSettings("isUnique_" + tool, true);
                                MainToolsTabStyleHandler.setToolTabStyle(sharedParameters, tool);
                            }
                        });
                        toolsUniqueStyleMenu.add(toolStyleOption);
                    }
                    globalMenu.add(toolsUniqueStyleMenu);

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

                    // Debug options
                    JMenu debugMenu = new JMenu("Debug Settings");
                    ButtonGroup debugButtonGroup = new ButtonGroup();

                    JRadioButtonMenuItem debugOptionDisabled = new JRadioButtonMenuItem(new AbstractAction("Disabled") {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            sharedParameters.allSettings.saveSettings("debugLevel", 0);
                            sharedParameters.debugLevel = 0;
                        }
                    });
                    if(sharedParameters.debugLevel == 0)
                        debugOptionDisabled.setSelected(true);

                    debugButtonGroup.add(debugOptionDisabled);
                    debugMenu.add(debugOptionDisabled);

                    JRadioButtonMenuItem debugOptionVerbose = new JRadioButtonMenuItem(new AbstractAction("Verbose") {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            sharedParameters.allSettings.saveSettings("debugLevel", 1);
                            sharedParameters.debugLevel = 1;
                        }
                    });
                    if(sharedParameters.debugLevel == 1)
                        debugOptionVerbose.setSelected(true);
                    debugButtonGroup.add(debugOptionVerbose);
                    debugMenu.add(debugOptionVerbose);

                    JRadioButtonMenuItem debugOptionVeryVerbose = new JRadioButtonMenuItem(new AbstractAction("Very Verbose") {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            sharedParameters.allSettings.saveSettings("debugLevel", 2);
                            sharedParameters.debugLevel = 2;
                        }
                    });
                    if(sharedParameters.debugLevel > 1)
                        debugOptionVeryVerbose.setSelected(true);
                    debugButtonGroup.add(debugOptionVeryVerbose);
                    debugMenu.add(debugOptionVeryVerbose);
                    globalMenu.add(debugMenu);

                    add(globalMenu);
                    addSeparator();

                    JMenuItem unloadExtension = new JMenuItem(new AbstractAction("Unload Extension") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            try {
                                int response = UIHelper.askConfirmMessage("Sharpener Extension Unload", "Are you sure you want to unload the extension?", new String[]{"Yes", "No"}, sharedParameters.get_mainFrame());
                                if (response == 0) {
                                    sharedParameters.callbacks.unloadExtension();
                                }
                            }catch(NoClassDefFoundError | Exception e){
                                // It seems the extension is dead and we are left with a top menu bar
                            }

                            try{
                                new Timer().schedule(
                                        new TimerTask() {
                                            @Override
                                            public void run() {
                                                // This is useful when the extension has been unloaded but the menu is still there because of an error
                                                // We should force removing the top menu bar from Burp using all native libraries
                                                JRootPane rootPane = topMenuForExtension.getRootPane();
                                                if(rootPane!=null){
                                                    JTabbedPane rootTabbedPane = (JTabbedPane) rootPane.getContentPane().getComponent(0);
                                                    JFrame mainFrame = (JFrame) rootTabbedPane.getRootPane().getParent();
                                                    JMenuBar mainMenuBar = mainFrame.getJMenuBar();
                                                    mainMenuBar.remove(topMenuForExtension);
                                                    mainFrame.validate();
                                                    mainFrame.repaint();
                                                }
                                            }
                                        },
                                        5000 // 5 seconds-delay to ensure all has been settled!
                                );
                            }catch (Exception e){

                            }
                        }
                    });
                    add(unloadExtension);

                    JMenuItem reloadAllSettings = new JMenuItem(new AbstractAction("Reload All Settings") {
                        @Override
                        public void actionPerformed(ActionEvent actionEvent) {
                            new Thread(new Runnable() {
                                @Override
                                public void run() {
                                    MainToolsTabStyleHandler.resetToolTabStylesFromSettings(sharedParameters);
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
                            int response = UIHelper.askConfirmMessage("Sharpener Extension: Reset All Settings & Unload", "Are you sure you want to remove all the settings and unload the extension?", new String[]{"Yes", "No"}, sharedParameters.get_mainFrame());
                            if (response == 0) {

                                // A bug in resetting settings in BurpExtenderUtilities should be fixed so we will give it another chance instead of using a workaround
                                // sharedParameters.resetAllSettings();
                                sharedParameters.preferences.resetAllSettings();
                                sharedParameters.callbacks.unloadExtension();
                            }
                        }
                    });

                    add(resetAllSettings);
                    addSeparator();

                    JCheckBoxMenuItem checkForUpdateOption = new JCheckBoxMenuItem("Check for Update on Start");
                    checkForUpdateOption.setToolTipText("Check is done by accessing its GitHub repository");
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
                    showProjectPage.setToolTipText("Will be opened in the default browser");
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
                    reportAnIssue.setToolTipText("Will be opened in the default browser");
                    add(reportAnIssue);

                    addSeparator();

                    Image mdsecLogoImg;
                    if(sharedParameters.isDarkMode){
                        mdsecLogoImg = ImageHelper.scaleImageToWidth(ImageHelper.loadImageResource(sharedParameters.extensionClass, "/MDSec-logo-grey.png"), 100);
                    }else{
                        mdsecLogoImg = ImageHelper.scaleImageToWidth(ImageHelper.loadImageResource(sharedParameters.extensionClass, "/MDSec-logo-blue.png"), 100);
                    }
                    ImageIcon mdsecLogoIcon = new ImageIcon(mdsecLogoImg);
                    JMenuItem mdsecLogoMenu = new JMenuItem(mdsecLogoIcon);
                    mdsecLogoMenu.setPreferredSize(new Dimension(100,50));

                    mdsecLogoMenu.setToolTipText("About this extension");
                    mdsecLogoMenu.addActionListener(new AbstractAction() {
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
                    add(mdsecLogoMenu);

                    // fixing the spacing when an icon is used - this used to work fine with old Java
                    for(var item:getMenuComponents()){
                        if(item instanceof JMenuItem){
                            if(((JMenuItem) item).getIcon() == null){
                                ((JMenuItem) item).setHorizontalTextPosition(SwingConstants.LEFT);
                            }
                        }
                    }

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
                    sharedParameters.allSettings.mainToolsTabSettings.loadSettings(); // this is to reflect the changes in the UI
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
                                        //topMenuForExtension.setFont(topMenuForExtension.getFont().deriveFont(topMenuForExtension.getFont().getStyle() ^ Font.BOLD)); // this would set the font so if we change them later in the UI, this menu will not be updated!
                                        topMenuForExtension.setFont(UIManager.getLookAndFeelDefaults().getFont(topMenuForExtension.getComponent()));
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
                sharedParameters.printDebugMessage("removing the menu bar the dirty way!");
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
