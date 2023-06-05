// Burp Suite Extension Name: Sharpener
// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)
// Released initially as open source by MDSec - https://www.mdsec.co.uk
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener

package com.mdsec.burp.sharpener;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.irsdl.burp.generic.BurpExtensionFeatures;
import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.generic.PropertiesHelper;
import com.mdsec.burp.sharpener.capabilities.pwnFox.PwnFoxProxyRequestHandler;
import com.mdsec.burp.sharpener.uiSelf.contextMenu.MainContextMenu;
import com.mdsec.burp.sharpener.uiSelf.suiteTab.MainSuiteTab;
import com.irsdl.generic.UIHelper;

import javax.swing.*;
import java.awt.*;
import java.beans.PropertyChangeListener;
import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class SharpenerMainClass implements BurpExtension, ExtensionUnloadingHandler {
    private SharpenerSharedParameters sharedParameters = null;
    private Boolean isActive = null;
    private boolean anotherExist = false;
    private PropertyChangeListener lookAndFeelPropChangeListener;

    @Override
    public void initialize(MontoyaApi api) {
        var features = new BurpExtensionFeatures();
        features.hasContextMenu = false;
        features.hasSuiteTab = false;
        features.hasHttpHandler = true;
        features.hasProxyHandler = false;
        features.isCommunityVersionCompatible = true;
        features.minSupportedMajorVersionInclusive = 2023;
        features.minSupportedMinorVersionInclusive = 1;
        var properties = PropertiesHelper.readProperties(this.getClass(), "/extension.properties");
        this.sharedParameters = new SharpenerSharedParameters(
                properties.getProperty("name"),
                properties.getProperty("version"),
                properties.getProperty("url"),
                properties.getProperty("issueTracker"),
                properties.getProperty("copyright"),
                properties.getProperty("propertiesFileUrl"),
                this, api, features);

        // set our extension name
        api.extension().setName(sharedParameters.extensionName);
        // registering itself to handle unloading
        api.extension().registerUnloadingHandler(this);

        if(!sharedParameters.isCompatibleWithCurrentBurpVersion){
            // This is not a compatible extension, what should we do?
            UIHelper.showWarningMessage("The " + sharedParameters.extensionName +
                    " extension is not compatible with the current version or edition of Burp Suite" +
                    "\nPlease look at the extension errors for more details.", sharedParameters.get_rootTabbedPaneUsingMontoya());
            api.extension().unload();
        }

        if(sharedParameters.features.hasHttpHandler){
            PwnFoxProxyRequestHandler pwnFoxProxyRequestHandler = new PwnFoxProxyRequestHandler(sharedParameters);
            api.proxy().registerRequestHandler(pwnFoxProxyRequestHandler);
        }

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
    public boolean getIsActive() {
        if (this.isActive == null)
            setIsActive(false);
        return this.isActive;
    }

    public void setIsActive(boolean isActive) {
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
        System.gc(); // probably will be ignored by Java anyway!
    }

    public void checkForUpdate() {
        // we need to see whether the extension is up-to-date by reading the propertiesFileUrl link
        new Thread(() -> {
            try{
                boolean isError = true;

                var buildGradleFileResponse = sharedParameters.montoyaApi.http().sendRequest(HttpRequest.httpRequestFromUrl(sharedParameters.extensionPropertiesUrl));

                var propertiesFile = buildGradleFileResponse.response().body().getBytes();

                if (propertiesFile != null) {
                    String buildGradleFileStr = new String(propertiesFile);
                    Pattern version_Pattern = Pattern.compile("version=([\\d.]+)");
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
                                            Desktop.getDesktop().browse(new URI(sharedParameters.extensionURL + "/releases/"));
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
                    sharedParameters.printlnError("Could not check for update from " + sharedParameters.extensionPropertiesUrl);
                }
            }catch(Exception e){
                sharedParameters.printlnError("Fatal error in checkForUpdate()");
                sharedParameters.printException(e);
            }
        }).start();
    }
}
