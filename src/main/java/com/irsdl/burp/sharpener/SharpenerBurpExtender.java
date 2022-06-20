// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener;

import burp.*;
import com.irsdl.burp.generic.BurpTitleAndIcon;
import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.uiModifiers.subTabs.SubTabActions;
import com.irsdl.burp.sharpener.uiModifiers.subTabs.SubTabWatcher;
import com.irsdl.burp.sharpener.uiModifiers.toolsTabs.MainToolsTabStyleHandler;
import com.irsdl.burp.sharpener.uiModifiers.toolsTabs.MainToolsTabWatcher;
import com.irsdl.burp.sharpener.uiModifiers.topMenu.TopMenuBar;
import com.irsdl.generic.HTTPMessageHelper;
import com.irsdl.generic.UIHelper;

import javax.swing.*;
import java.awt.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class SharpenerBurpExtender implements IBurpExtender, ITab, IExtensionStateListener, IProxyListener {
    //public static MainExtensionClass instance;
    private String version = "1.71";
    private IBurpExtender instance;
    private SharpenerSharedParameters sharedParameters = null;
    private Boolean isActive = null;
    private JPanel dummyPanel;
    private TopMenuBar topMenuBar;
    private SubTabWatcher subTabWatcher;
    private MainToolsTabWatcher mainToolsTabWatcher;
    private Boolean anotherExist = false;
    private PropertyChangeListener lookAndFeelPropChangeListener;

    public synchronized Boolean getIsActive() {
        if (this.isActive == null)
            setIsActive(false);
        return this.isActive;
    }

    public synchronized void setIsActive(Boolean isActive) {
        this.isActive = isActive;
    }

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        //MainExtensionClass.instance = this;
        this.instance = this;
        this.sharedParameters = new SharpenerSharedParameters(version, "Sharpener", "https://github.com/mdsecresearch/BurpSuiteSharpener", "https://github.com/mdsecresearch/BurpSuiteSharpener/issues", instance, callbacks);

        // set our extension name
        callbacks.setExtensionName(sharedParameters.extensionName);

        callbacks.registerExtensionStateListener(this);
        callbacks.registerProxyListener(this);

        // create our UI
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                dummyPanel = new JPanel(); //Will be removed shortly after it's added, doesn't need to be anything special at the moment!
                callbacks.addSuiteTab(SharpenerBurpExtender.this);
                load(false);
            }
        });

    }

    @Override
    public String getTabCaption() {
        return sharedParameters.extensionName;
    }

    @Override
    public Component getUiComponent() {
        return dummyPanel;
    }

    @Override
    public void extensionUnloaded() {
        unload();
    }

    public void load(boolean isDirty) {
        if (!isDirty) {
            sharedParameters.printDebugMessage("is not dirty: setUIParametersFromExtensionTab");
            sharedParameters.setUIParametersFromExtensionTab(dummyPanel, 10);
        } else {
            sharedParameters.printDebugMessage("is dirty: unload");
            unload();
        }

        if ((sharedParameters.get_isUILoaded() && !isDirty) || isDirty) {

            if (!isDirty) {
                sharedParameters.printDebugMessage("is not dirty: removeSuiteTab");
                sharedParameters.callbacks.removeSuiteTab(SharpenerBurpExtender.this); // we don't need this
            }

            if (!BurpUITools.isMenubarLoaded(sharedParameters.extensionName, sharedParameters.get_mainMenuBar()) || isDirty) {
                sharedParameters.printDebugMessage("Loading all settings!");
                // Loading all settings!
                sharedParameters.allSettings = new SharpenerGeneralSettings(sharedParameters);

                sharedParameters.callbacks.registerScopeChangeListener(new IScopeChangeListener() {
                    @Override
                    public void scopeChanged() {
                        try {
                            URL burpExtenderUtilitiesURL = new URL("https://project-extension-preference-store-do-not-delete:65535/");
                            if (!sharedParameters.callbacks.isInScope(burpExtenderUtilitiesURL) && !sharedParameters.isScopeChangeDecisionOngoing) {
                                sharedParameters.isScopeChangeDecisionOngoing = true;
                                int scopeDecision = UIHelper.askConfirmMessage("Scope Removal Confirmation",
                                        sharedParameters.extensionName + " settings cannot be saved. Do you want to add it back to the scope?",
                                        new String[]{"Yes", "No"}, sharedParameters.get_mainFrame());

                                if (scopeDecision == 0) {
                                    // There is a bug in Burp Suite which shows UI error if we do not switch to another tab at this point!
                                    if (!BurpUITools.switchToMainTab("Dashboard", sharedParameters.get_rootTabbedPane()))
                                        if (!BurpUITools.switchToMainTab("Proxy", sharedParameters.get_rootTabbedPane()))
                                            BurpUITools.switchToMainTab("User options", sharedParameters.get_rootTabbedPane());

                                    new java.util.Timer().schedule(
                                            new java.util.TimerTask() {
                                                @Override
                                                public void run() {
                                                    sharedParameters.callbacks.includeInScope(burpExtenderUtilitiesURL);
                                                }
                                            },
                                            2000
                                    );
                                    UIHelper.showWarningMessage("Please wait for 5 seconds before clicking on the Target tab to prevent a Burp Suite internal bug when updating the scope!", sharedParameters.get_rootTabbedPane());
                                }

                                new java.util.Timer().schedule(
                                        new java.util.TimerTask() {
                                            @Override
                                            public void run() {
                                                sharedParameters.isScopeChangeDecisionOngoing = false;
                                            }
                                        },
                                        5000
                                );
                            }
                        } catch (MalformedURLException e) {
                            // this URL comes from https://github.com/CoreyD97/BurpExtenderUtilities/blob/14d526fbc0cbc93f9970e15d94f272f5dcb97dc3/src/main/java/com/coreyd97/BurpExtenderUtilities/ProjectSettingStore.java#L34
                        }
                    }
                });

                // Adding listeners to Main Tool Tabs
                if (sharedParameters.get_rootTabbedPane() != null) {
                    sharedParameters.printDebugMessage("Adding listeners to main tools' tabs");
                    mainToolsTabWatcher = new MainToolsTabWatcher(sharedParameters, mouseEvent -> {
                        //SubTabActions.tabClicked(mouseEvent, sharedParameters);
                    });
                    mainToolsTabWatcher.addTabListener(sharedParameters.get_rootTabbedPane());
                }

                // Adding MiddleClick / RightClick+Alt to Repeater and Intruder
                if (sharedParameters.get_rootTabbedPane() != null) {
                    sharedParameters.printDebugMessage("Adding MiddleClick / RightClick+Alt to Repeater and Intruder");
                    subTabWatcher = new SubTabWatcher(sharedParameters, mouseEvent -> {
                        SubTabActions.tabClicked(mouseEvent, sharedParameters);
                    });
                    subTabWatcher.addTabListener(sharedParameters.get_rootTabbedPane());
                }

                // Adding the top menu
                try {
                    if (topMenuBar != null) {
                        sharedParameters.printDebugMessage("Removing the top menu before adding it again");
                        topMenuBar.removeTopMenuBar();
                    }
                    sharedParameters.printDebugMessage("Adding the top menu");
                    topMenuBar = new TopMenuBar(sharedParameters);
                    topMenuBar.addTopMenuBar();
                } catch (Exception e) {
                    sharedParameters.stderr.println("Error in creating the top menu: " + e.getMessage());
                }

                // This is a dirty hack when LookAndFeel changes in the middle and we lose the style!
                lookAndFeelPropChangeListener = new PropertyChangeListener() {
                    @Override
                    public void propertyChange(PropertyChangeEvent evt) {
                        sharedParameters.unloadWithoutSave = true; // we need to unload the extension without saving it as major change in UI has occurred (switch to dark/light mode)
                        new java.util.Timer().schedule(
                                new java.util.TimerTask() {
                                    @Override
                                    public void run() {
                                        SwingUtilities.invokeLater(new Runnable() {
                                            @Override
                                            public void run() {
                                                sharedParameters.printDebugMessage("lookAndFeelPropChangeListener");
                                                sharedParameters.defaultSubTabObject = null;
                                                UIHelper.showWarningMessage("Due to a major UI change, the " + sharedParameters.extensionName + " extension needs to be unload. Please load it manually.", sharedParameters.get_mainFrame());
                                                BurpUITools.switchToMainTab("Extender", sharedParameters.get_rootTabbedPane());
                                                sharedParameters.callbacks.unloadExtension();
                                            }
                                        });
                                    }
                                },
                                2000
                        );
                    }
                };

                sharedParameters.printDebugMessage("addPropertyChangeListener: lookAndFeelPropChangeListener");
                UIManager.addPropertyChangeListener(lookAndFeelPropChangeListener);

            } else {
                anotherExist = true;
                String errMessage = "The top menu for this extension already exists. Has it been loaded twice?";
                sharedParameters.printlnError(errMessage);
                UIHelper.showWarningMessage(errMessage, sharedParameters.get_mainFrame());
                sharedParameters.callbacks.unloadExtension();
            }
        } else {
            sharedParameters.printlnError("UI cannot be loaded... try again");
            sharedParameters.callbacks.unloadExtension();
        }
    }

    public void unload() {
        sharedParameters.printDebugMessage("unload");

        // reattaching related tools before working on them!
        if (BurpUITools.reattachTools(sharedParameters.subTabSupportedTabs, sharedParameters.get_mainMenuBar())) {
            try {
                sharedParameters.printDebugMessage("reattaching");
                // to make sure UI has been updated
                sharedParameters.printlnOutput("Detached windows were found. We need to wait for a few seconds after reattaching the tabs.");
                Thread.sleep(3000);
            } catch (Exception e) {

            }
        }

        if (sharedParameters.get_isUILoaded() && !anotherExist) {
            try {


                sharedParameters.printDebugMessage("removePropertyChangeListener: lookAndFeelPropChangeListener");
                UIManager.removePropertyChangeListener(lookAndFeelPropChangeListener);

                // remove listener for main tools' tabs
                if (mainToolsTabWatcher != null && sharedParameters.get_isUILoaded()) {
                    mainToolsTabWatcher.removeTabListener(sharedParameters.get_rootTabbedPane());
                }

                sharedParameters.printDebugMessage("removing tab listener on tabs in Repeater and Intruder");
                // remove tab listener on tabs in Repeater and Intruder
                if (subTabWatcher != null && sharedParameters.get_isUILoaded()) {
                    subTabWatcher.removeTabListener(sharedParameters.get_rootTabbedPane());
                }

                sharedParameters.printDebugMessage("undo the Burp main tool tabs");
                // undo the Burp main tool tabs
                MainToolsTabStyleHandler.unsetAllToolTabStyles(sharedParameters);

                sharedParameters.printDebugMessage("undo subtabs styles");

                // undo subtabs styles
                sharedParameters.allSettings.subTabSettings.unsetSubTabsStyle();

                sharedParameters.printDebugMessage("reset Burp title and icon");
                // reset Burp title and icon
                BurpTitleAndIcon.resetTitle(sharedParameters);
                BurpTitleAndIcon.resetIcon(sharedParameters);

                sharedParameters.printDebugMessage("removing toolbar menu");
                // removing toolbar menu
                if (topMenuBar != null)
                    topMenuBar.removeTopMenuBar();
            } catch (Exception e) {
                sharedParameters.printlnError("An error has occurred when unloading the " + sharedParameters.extensionName + " extension.");
                sharedParameters.printDebugMessage(e.getMessage());
                e.printStackTrace(sharedParameters.stderr);
                sharedParameters.printlnError("Top menu will be removed! If that does not work, use the Unload option of the top menu");
                if (topMenuBar != null)
                    topMenuBar.removeTopMenuBar();
                UIHelper.showWarningMessage(sharedParameters.extensionName + " extension has been closed with an error.\r\n" +
                                "You may need to restart Burp Suite.\r\n" +
                                "Please consider looking at the error and reporting it to the GitHub repository:\r\n" +
                                sharedParameters.extensionURL
                        , topMenuBar);
            }

            // removing the menu bar can be problematic so we need to check again
            //TopMenuBar.removeTopMenuBarLastResort(sharedParameters, true);

            /*
            // Burp goes to a deadlock when calling revalidate at this point
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    new Thread(() -> {
                        sharedParameters.printDebugMessages("revalidate");
                        sharedParameters.get_mainFrame().revalidate();
                        sharedParameters.printDebugMessages("repaint");
                        sharedParameters.get_mainFrame().repaint();
                    }).start();
                }
            });
            */

        }

        sharedParameters.printDebugMessage("UI changes have been removed.");
    }

    public void checkForUpdate() {
        // we need to see whether the extension is up to date by reading https://raw.githubusercontent.com/mdsecresearch/BurpSuiteSharpener/main/build.gradle
        new Thread(new Runnable() {
            @Override
            public void run() {
                boolean isError = true;
                String rawRequest = "GET /mdsecresearch/BurpSuiteSharpener/main/build.gradle HTTP/1.1\r\nHOST: raw.githubusercontent.com\r\n\r\n";
                byte[] buildgradleFile = sharedParameters.callbacks.makeHttpRequest("raw.githubusercontent.com", 443, true, rawRequest.getBytes());

                if (buildgradleFile != null) {
                    String buildgradleFileStr = new String(buildgradleFile);
                    Pattern MY_PATTERN = Pattern.compile("version '([\\d\\.]+)");
                    Matcher m = MY_PATTERN.matcher(buildgradleFileStr);
                    if (m.find()) {
                        String githubVersionStr = m.group(1);
                        try {
                            double currentVersion = Double.parseDouble(sharedParameters.version);
                            double githubVersion = Double.parseDouble(githubVersionStr);

                            if (githubVersion > currentVersion) {
                                sharedParameters.printlnOutput(sharedParameters.extensionName + " is outdated. The latest version is: " + githubVersionStr);
                                new Thread(new Runnable() {
                                    @Override
                                    public void run() {
                                        int answer = UIHelper.askConfirmMessage("A new version of " + sharedParameters.extensionName + " is available", "Do you want to open the " + sharedParameters.extensionName + " project page to download the latest version?", new String[]{"Yes", "No"}, sharedParameters.get_mainFrame());
                                        if (answer == 0) {
                                            try {
                                                Desktop.getDesktop().browse(new URI(sharedParameters.extensionURL + "/tree/main/release"));
                                            } catch (Exception e) {
                                                sharedParameters.printlnError(e.getMessage());
                                            }
                                        }
                                    }
                                }).start();

                            } else if (currentVersion > githubVersion) {
                                sharedParameters.printlnOutput(sharedParameters.extensionName + " is more than up to date; do you have a time machine?");
                            } else {
                                sharedParameters.printlnOutput(sharedParameters.extensionName + " is up to date");
                            }
                            isError = false;
                        } catch (Exception e) {

                        }
                    }
                }

                if (isError) {
                    sharedParameters.printDebugMessage("Could not check for update from https://raw.githubusercontent.com/mdsecresearch/BurpSuiteSharpener/main/build.gradle");
                }
            }

        }).start();
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        if (!messageIsRequest) return;
        var messageInfo = message.getMessageInfo();

        if (messageInfo != null) {
            boolean pwnFoxSupportCapability = sharedParameters.preferences.safeGetSetting("pwnFoxSupportCapability", false);

            if (pwnFoxSupportCapability) {
                // From https://github.com/yeswehack/PwnFox/pull/8/commits/27bdb409ec7727f021f739abf50bbb9eb6c26e85
                var requestInfo = sharedParameters.callbacks.getHelpers().analyzeRequest(messageInfo);
                var body = messageInfo.getRequest();
                var bodyAndHeader = HTTPMessageHelper.getHeaderAndBody(body, requestInfo.getBodyOffset());
                var headerList = HTTPMessageHelper.getHeadersListFromHeader(bodyAndHeader.get(0));
                var pwnFoxColor = HTTPMessageHelper.getFirstHeaderValueByNameFromHeaders(headerList, "X-PwnFox-Color", false);
                if (!pwnFoxColor.isEmpty()) {
                    var cleanHeaders = HTTPMessageHelper.removeHeadersByName(headerList, "X-PwnFox-Color");
                    messageInfo.setHighlight(pwnFoxColor);
                    messageInfo.setRequest(sharedParameters.callbacks.getHelpers().buildHttpMessage(cleanHeaders, bodyAndHeader.get(1)));
                }
            }
        }
    }
}
