// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import burp.ITab;
import com.irsdl.burp.generic.BurpTitleAndIcon;
import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.uimodifiers.TopMenuBar;
import com.irsdl.burp.sharpener.uimodifiers.subtabs.SubTabActions;
import com.irsdl.burp.sharpener.uimodifiers.subtabs.SubTabWatcher;
import com.irsdl.burp.sharpener.uimodifiers.toolstabs.ToolsTabStyleHandler;
import com.irsdl.generic.UIHelper;

import javax.swing.*;
import java.awt.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;


public class SharpenerBurpExtender implements IBurpExtender, ITab, IExtensionStateListener {
    //public static MainExtensionClass instance;
    private String version = "1.03";
    private IBurpExtender instance;
    private SharpenerSharedParameters sharedParameters = null;
    private Boolean isActive = null;
    private JPanel dummyPanel;
    private TopMenuBar ttm;
    private SubTabWatcher subTabWatcher;
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
        this.sharedParameters = new SharpenerSharedParameters(version, "Sharpener", "https://github.com/mdsecresearch/BurpSuiteSharpener/", "https://github.com/mdsecresearch/BurpSuiteSharpener/issues", instance, callbacks);

        // set our extension name
        callbacks.setExtensionName(sharedParameters.extensionName);

        callbacks.registerExtensionStateListener(this);


        // create our UI
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                dummyPanel = new JPanel(); //Will be removed shortly after it's added, doesn't need to be anything special at the moment!
                callbacks.addSuiteTab(SharpenerBurpExtender.this);
                new Thread(() -> {
                    load(false);
                }).start();
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
            sharedParameters.printDebugMessages("is not dirty: setUIParametersFromExtensionTab");
            sharedParameters.setUIParametersFromExtensionTab(dummyPanel, 10);
        } else {
            sharedParameters.printDebugMessages("is dirty: unload");
            unload();
        }

        if ((sharedParameters.get_isUILoaded() && !isDirty) || isDirty) {
            if (!isDirty) {
                sharedParameters.printDebugMessages("is not dirty: removeSuiteTab");
                sharedParameters.callbacks.removeSuiteTab(SharpenerBurpExtender.this); // we don't need this
            }

            if (!BurpUITools.isMenubarLoaded(sharedParameters.extensionName, sharedParameters.get_mainMenuBar()) || isDirty) {
                sharedParameters.printDebugMessages("Loading all settings!");
                // Loading all settings!
                sharedParameters.allSettings = new SharpenerGeneralSettings(sharedParameters);

                // Adding MiddleClick / RightClick+Alt to Repeater and Intruder
                if (sharedParameters.get_rootTabbedPane() != null) {
                    sharedParameters.printDebugMessages("Adding MiddleClick / RightClick+Alt to Repeater and Intruder");
                    subTabWatcher = new SubTabWatcher(sharedParameters, mouseEvent -> {
                        SubTabActions.tabClicked(mouseEvent, sharedParameters);
                    });
                    subTabWatcher.addTabListener(sharedParameters.get_rootTabbedPane());
                }

                // Adding the top menu
                try {
                    if (ttm != null) {
                        sharedParameters.printDebugMessages("Removing the top menu before adding it again");
                        ttm.removeTopMenuBar();
                    }
                    sharedParameters.printDebugMessages("Adding the top menu");
                    ttm = new TopMenuBar(sharedParameters);
                    ttm.addTopMenuBar();
                } catch (Exception e) {
                    sharedParameters.stderr.println("Error in creating the top menu: " + e.getMessage());
                }

                // This is a dirty hack when LookAndFeel changes in the middle and we lose the style!
                lookAndFeelPropChangeListener = new PropertyChangeListener() {
                    @Override
                    public void propertyChange(PropertyChangeEvent evt) {
                        new java.util.Timer().schedule(
                                new java.util.TimerTask() {
                                    @Override
                                    public void run() {
                                        sharedParameters.printDebugMessages("lookAndFeelPropChangeListener");
                                        sharedParameters.defaultSubTabObject = null;
                                        UIHelper.showWarningMessage("Due to the major UI change, it is recommended to reload the " + sharedParameters.extensionName + " extension.", sharedParameters.get_mainFrame());
                                    }
                                },
                                2000
                        );
                    }
                };

                sharedParameters.printDebugMessages("addPropertyChangeListener: lookAndFeelPropChangeListener");
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
        sharedParameters.printDebugMessages("unload");

        // reattaching related tools before working on them!
        if (BurpUITools.reattachTools(sharedParameters.subTabWatcherSupportedTabs, sharedParameters.get_mainMenuBar())) {
            try {
                sharedParameters.printDebugMessages("reattaching");
                // to make sure UI has been updated
                sharedParameters.printlnOutput("Detached windows were found. We need to wait for a few seconds after reattaching the tabs.");
                Thread.sleep(3000);
            } catch (Exception e) {

            }
        }

        if (sharedParameters.get_isUILoaded() && !anotherExist) {
            sharedParameters.printDebugMessages("removing toolbar menu");
            // removing toolbar menu
            if (ttm != null)
                ttm.removeTopMenuBar();

            sharedParameters.printDebugMessages("removing tab listener on tabs in Repeater and Intruder");
            // remove tab listener on tabs in Repeater and Intruder
            if (subTabWatcher != null && sharedParameters.get_isUILoaded()) {
                subTabWatcher.removeTabListener(sharedParameters.get_rootTabbedPane());
            }

            sharedParameters.printDebugMessages("undo the Burp main tool tabs");
            // undo the Burp main tool tabs
            ToolsTabStyleHandler.unsetAllToolTabStyles(sharedParameters);

            sharedParameters.printDebugMessages("undo subtabs styles");
            // undo subtabs styles
            sharedParameters.allSettings.subTabSettings.unsetSubTabsStyle();

            sharedParameters.printDebugMessages("reset Burp title and icon");
            // reset Burp title and icon
            BurpTitleAndIcon.resetTitleAndIcon(sharedParameters);

            // removing the menu bar can be problematic so we need to check again
            TopMenuBar.removeTopMenuBarLastResort(sharedParameters);

            sharedParameters.printDebugMessages("removePropertyChangeListener: lookAndFeelPropChangeListener");
            UIManager.removePropertyChangeListener(lookAndFeelPropChangeListener);

            /*
            // Burp goes to a deadlock when calling revalidate at this point
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    new Thread(() -> {
                        if(sharedParameters.isDebug)
                            sharedParameters.printlnOutput("revalidate");
                        sharedParameters.get_mainFrame().revalidate();
                        if(sharedParameters.isDebug)
                            sharedParameters.printlnOutput("repaint");
                        sharedParameters.get_mainFrame().repaint();
                    }).start();
                }
            });
            */

        }

        sharedParameters.printDebugMessages("UI changes have been removed.");
    }

}
