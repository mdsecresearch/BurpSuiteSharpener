// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.irsdl.burp.generic.BurpExtensionFeatures;
import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.capabilities.pwnFox.PwnFoxProxyListener;
import com.irsdl.burp.sharpener.uiSelf.contextMenu.MainContextMenu;
import com.irsdl.burp.sharpener.uiSelf.suiteTab.MainSuiteTab;
import com.irsdl.generic.UIHelper;

import javax.swing.*;
import java.awt.*;
import java.beans.PropertyChangeListener;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class SharpenerBurpExtender implements BurpExtension, ExtensionUnloadingHandler {
    private SharpenerSharedParameters sharedParameters = null;
    private Boolean isActive = null;
    private boolean anotherExist = false;
    private PropertyChangeListener lookAndFeelPropChangeListener;

    @Override
    public void initialize(MontoyaApi api) {
        var features = new BurpExtensionFeatures();
        features.hasContextMenu = false;
        features.hasSuiteTab = false;
        features.isCommunityVersionCompatible = true;
        features.minSupportedMajorVersionInclusive = 2023;
        features.minSupportedMinorVersionInclusive = 1;

        this.sharedParameters = new SharpenerSharedParameters("3.1", "Sharpener", "https://github.com/mdsecresearch/BurpSuiteSharpener", "https://github.com/mdsecresearch/BurpSuiteSharpener/issues", this, api, features);

        // set our extension name
        api.extension().setName(sharedParameters.extensionName);

        api.extension().registerUnloadingHandler(this);

        if(!sharedParameters.isCompatibleWithCurrentBurpVersion){
            // This is not a compatible extension, what should we do?
            UIHelper.showWarningMessage("The " + sharedParameters.extensionName +
                    " extension is not compatible with the current version or edition of Burp Suite" +
                    "\nPlease look at the extension errors for more details.", sharedParameters.get_rootTabbedPaneUsingMontoya());
            api.extension().unload();
        }

        PwnFoxProxyListener pwnFoxProxyListener = new PwnFoxProxyListener(sharedParameters);
        api.proxy().registerRequestHandler(pwnFoxProxyListener);

        // create our UI
        SwingUtilities.invokeLater(() -> {
            // we no longer need to create an extension GUI tab to get access to the jFrame - Montoya can give us access

            if(sharedParameters.features.hasSuiteTab){
                sharedParameters.extensionSuiteTab = new MainSuiteTab();
                sharedParameters.extensionSuiteTabRegistration = api.userInterface().registerSuiteTab(sharedParameters.extensionName, sharedParameters.extensionSuiteTab);
            }

            if(sharedParameters.features.hasContextMenu){
                sharedParameters.extensionMainContextMenu = new MainContextMenu();
                sharedParameters.extensionContextMenuRegistration = api.userInterface().registerContextMenuItemsProvider(sharedParameters.extensionMainContextMenu);
            }

            load(false);
            sharedParameters.printlnOutput(sharedParameters.extensionName + " has been loaded successfully.");
        });
    }
    public synchronized boolean getIsActive() {
        if (this.isActive == null)
            setIsActive(false);
        return this.isActive;
    }

    public synchronized void setIsActive(boolean isActive) {
        this.isActive = isActive;
    }

    @Override
    public void extensionUnloaded() {
        unload();
    }

    public void load(boolean isDirty) {
        sharedParameters.printDebugMessage("load - isDirty: " + isDirty);
        try{
            if (!isDirty) {
                sharedParameters.printDebugMessage("is not dirty: setUIParametersUsingMontoya");
                sharedParameters.setUIParametersUsingMontoya(10);
            } else {
                sharedParameters.printDebugMessage("is dirty: unload");
                unload();
            }

            if (sharedParameters.get_isUILoaded() || isDirty) {
                if (!BurpUITools.isMenuBarLoaded(sharedParameters.extensionName, sharedParameters.get_mainMenuBarUsingMontoya()) || isDirty) {
                    sharedParameters.printDebugMessage("Loading all settings!");
                    // Loading all settings!
                    sharedParameters.allSettings = new SharpenerGeneralSettings(sharedParameters);

                    sharedParameters.montoyaApi.scope().registerScopeChangeHandler(scopeChange -> {
                        try {
                            URL burpExtenderUtilitiesURL = new URL("https://project-extension-preference-store-do-not-delete:65535/");
                            if (!sharedParameters.montoyaApi.scope().isInScope(burpExtenderUtilitiesURL.toString()) && !sharedParameters.isScopeChangeDecisionOngoing) {
                                sharedParameters.isScopeChangeDecisionOngoing = true;
                                int scopeDecision = UIHelper.askConfirmMessage("Scope Removal Confirmation",
                                        sharedParameters.extensionName + " settings cannot be saved. Do you want to add it back to the scope?",
                                        new String[]{"Yes", "No"}, sharedParameters.get_mainFrameUsingMontoya());

                                if (scopeDecision == 0) {
                                    // There is a bug in Burp Suite which shows UI error if we do not switch to another tab at this point!
                                    if (!BurpUITools.switchToMainTab("Dashboard", sharedParameters.get_rootTabbedPaneUsingMontoya()))
                                        if (!BurpUITools.switchToMainTab("Proxy", sharedParameters.get_rootTabbedPaneUsingMontoya()))
                                            BurpUITools.switchToMainTab("User options", sharedParameters.get_rootTabbedPaneUsingMontoya());

                                    new java.util.Timer().schedule(
                                            new java.util.TimerTask() {
                                                @Override
                                                public void run() {
                                                    sharedParameters.montoyaApi.scope().includeInScope(burpExtenderUtilitiesURL.toString());
                                                }
                                            },
                                            2000
                                    );
                                    UIHelper.showWarningMessage("Please wait for 5 seconds before clicking on the Target tab to prevent a Burp Suite internal bug when updating the scope!", sharedParameters.get_rootTabbedPaneUsingMontoya());
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
                    });

                    // This is a dirty hack when LookAndFeel changes in the middle, and we lose the style!
                    lookAndFeelPropChangeListener = evt -> {
                        sharedParameters.unloadWithoutSave = true; // we need to unload the extension without saving it as major change in UI has occurred (switch to dark/light mode)
                        new java.util.Timer().schedule(
                                new java.util.TimerTask() {
                                    @Override
                                    public void run() {
                                        SwingUtilities.invokeLater(() -> {
                                            sharedParameters.printDebugMessage("lookAndFeelPropChangeListener");
                                            sharedParameters.defaultTabFeaturesObjectStyle = null;
                                            UIHelper.showWarningMessage("Due to a major UI change, the " + sharedParameters.extensionName + " extension needs to be unload. Please load it manually.", sharedParameters.get_mainFrameUsingMontoya());
                                            BurpUITools.switchToMainTab("Extender", sharedParameters.get_rootTabbedPaneUsingMontoya());
                                            sharedParameters.montoyaApi.extension().unload();
                                        });
                                    }
                                },
                                2000
                        );
                    };

                    sharedParameters.printDebugMessage("addPropertyChangeListener: lookAndFeelPropChangeListener");
                    UIManager.addPropertyChangeListener(lookAndFeelPropChangeListener);

                } else {
                    anotherExist = true;
                    String errMessage = "The top menu for this extension already exists. Has it been loaded twice?";
                    sharedParameters.printlnError(errMessage);
                    UIHelper.showWarningMessage(errMessage, sharedParameters.get_mainFrameUsingMontoya());
                    sharedParameters.montoyaApi.extension().unload();
                }
            } else {
                sharedParameters.printlnError("UI cannot be loaded... try again");
                sharedParameters.montoyaApi.extension().unload();
            }
        }catch (Exception e){
            sharedParameters.printlnError("Fatal error in loading the extension");
            sharedParameters.printException(e);
        }
    }

    public void unload() {
        sharedParameters.printDebugMessage("unload");
        try{
            // reattaching related tools before working on them!
            if (BurpUITools.reattachTools(sharedParameters.subTabSupportedTabs, sharedParameters.get_mainMenuBarUsingMontoya())) {
                try {
                    sharedParameters.printDebugMessage("reattaching");
                    // to make sure UI has been updated
                    sharedParameters.printlnOutput("Detached windows were found. We need to wait for a few seconds after reattaching the tabs.");
                    Thread.sleep(3000);
                } catch (Exception e) {
                    sharedParameters.printDebugMessage("Error in reattaching the tools");
                }
            }

            if (sharedParameters.get_isUILoaded() && !anotherExist) {
                try {
                    sharedParameters.printDebugMessage("removePropertyChangeListener: lookAndFeelPropChangeListener");
                    UIManager.removePropertyChangeListener(lookAndFeelPropChangeListener);

                    sharedParameters.allSettings.unloadSettings();

                } catch (Exception e) {
                    sharedParameters.printlnError("An error has occurred when unloading the " + sharedParameters.extensionName + " extension.");
                    sharedParameters.printDebugMessage(e.getMessage());
                    e.printStackTrace(sharedParameters.stderr);
                    sharedParameters.printlnError("Top menu will be removed! If that does not work, use the Unload option of the top menu");
                    if (sharedParameters.topMenuBar != null)
                        sharedParameters.topMenuBar.removeTopMenuBar();
                    UIHelper.showWarningMessage(sharedParameters.extensionName + " extension has been closed with an error.\r\n" +
                                    "You may need to restart Burp Suite.\r\n" +
                                    "Please consider looking at the error and reporting it to the GitHub repository:\r\n" +
                                    sharedParameters.extensionURL
                            , sharedParameters.topMenuBar);
                }
            }

            sharedParameters.printDebugMessage("UI changes have been removed.");
        }catch (Exception e){
            sharedParameters.printlnError("Fatal error in unloading the extension");
            sharedParameters.printException(e);
        }
    }

    public void checkForUpdate() {
        // we need to see whether the extension is up-to-date by reading https://raw.githubusercontent.com/mdsecresearch/BurpSuiteSharpener/main/build.gradle
        new Thread(() -> {
            try{
                boolean isError = true;
                String rawRequest = "GET /mdsecresearch/BurpSuiteSharpener/main/build.gradle HTTP/1.1\r\nHOST: raw.githubusercontent.com\r\n\r\n";

                var buildGradleFileResponse = sharedParameters.montoyaApi.http().sendRequest(HttpRequest.httpRequest(
                        HttpService.httpService("raw.githubusercontent.com", 443, true)
                        , rawRequest
                ));

                var buildGradleFile = buildGradleFileResponse.response().body().getBytes();

                if (buildGradleFile != null) {
                    String buildGradleFileStr = new String(buildGradleFile);
                    Pattern version_Pattern = Pattern.compile("version '([\\d.]+)");
                    Matcher m = version_Pattern.matcher(buildGradleFileStr);
                    if (m.find()) {
                        String githubVersionStr = m.group(1);
                        try {
                            double currentVersion = Double.parseDouble(sharedParameters.version);
                            double githubVersion = Double.parseDouble(githubVersionStr);

                            if (githubVersion > currentVersion) {
                                sharedParameters.printlnOutput(sharedParameters.extensionName + " is outdated. The latest version is: " + githubVersionStr);
                                new Thread(() -> {
                                    int answer = UIHelper.askConfirmMessage("A new version of " + sharedParameters.extensionName + " is available", "Do you want to open the " + sharedParameters.extensionName + " project page to download the latest version?", new String[]{"Yes", "No"}, sharedParameters.get_mainFrameUsingMontoya());
                                    if (answer == 0) {
                                        try {
                                            Desktop.getDesktop().browse(new URI(sharedParameters.extensionURL + "/tree/main/release"));
                                        } catch (Exception e) {
                                            sharedParameters.printlnError(e.getMessage());
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
                            sharedParameters.printDebugMessage("Error in SharpenerBurpExtender.checkForUpdate()" + e.getMessage());
                        }
                    }
                }
                if (isError) {
                    sharedParameters.printDebugMessage("Could not check for update from https://raw.githubusercontent.com/mdsecresearch/BurpSuiteSharpener/main/build.gradle");
                }
            }catch(Exception e){
                sharedParameters.printlnError("Fatal error in checkForUpdate()");
                sharedParameters.printException(e);
            }
        }).start();
    }
}
