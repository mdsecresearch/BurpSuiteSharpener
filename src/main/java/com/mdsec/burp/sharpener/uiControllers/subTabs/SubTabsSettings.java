// Burp Suite Extension Name: Sharpener
// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)
// Released initially as open source by MDSec - https://www.mdsec.co.uk
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener

package com.mdsec.burp.sharpener.uiControllers.subTabs;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.reflect.TypeToken;
import com.irsdl.burp.generic.BurpExtensionSharedParameters;
import com.irsdl.burp.generic.BurpUITools;
import com.mdsec.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.objects.PreferenceObject;
import com.irsdl.objects.StandardSettings;
import com.mdsec.burp.sharpener.objects.TabFeaturesObject;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;


public class SubTabsSettings extends StandardSettings {

    public String lastSavedImageLocation;
    public boolean isFirstLoad;
    private Lock updateInProgressLock = new ReentrantLock();

    private SubTabsListeners subTabsListeners;
    public SubTabsSettings(SharpenerSharedParameters sharedParameters) {
        super(sharedParameters);
        sharedParameters.printDebugMessage("SubTabsSettings");
    }

    @Override
    public void init() {
        lastSavedImageLocation = "";
        isFirstLoad = true;
    }

    @Override
    public Collection<PreferenceObject> definePreferenceObjectCollection() {
        Collection<PreferenceObject> preferenceObjectCollection = new ArrayList<>();
        for (BurpUITools.MainTabs tool : sharedParameters.subTabSupportedTabs) {
            PreferenceObject preferenceObject = new PreferenceObject("TabFeaturesObject_Array_" + tool, new TypeToken<HashMap<String, TabFeaturesObject>>() {
            }.getType(), null, Preferences.Visibility.PROJECT);
            preferenceObjectCollection.add(preferenceObject);

            PreferenceObject preferenceObject_isScrollable_SubTab = new PreferenceObject("isScrollable_" + tool, Boolean.TYPE, false, Preferences.Visibility.PROJECT);
            preferenceObjectCollection.add(preferenceObject_isScrollable_SubTab);

            PreferenceObject preferenceObject_mouseWheelToScroll_SubTab = new PreferenceObject("mouseWheelToScroll_" + tool, Boolean.TYPE, false, Preferences.Visibility.PROJECT);
            preferenceObjectCollection.add(preferenceObject_mouseWheelToScroll_SubTab);

            PreferenceObject preferenceObject_minimizeSize_SubTab = new PreferenceObject("minimizeSize_" + tool, Boolean.TYPE, false, Preferences.Visibility.PROJECT);
            preferenceObjectCollection.add(preferenceObject_minimizeSize_SubTab);

            PreferenceObject preferenceObject_isTabFixedPositionUI_SubTab;
            if (sharedParameters.burpMajorVersion > 2022 || (sharedParameters.burpMajorVersion == 2022 && sharedParameters.burpMinorVersion >= 3)) {
                preferenceObject_isTabFixedPositionUI_SubTab = new PreferenceObject("isTabFixedPosition_" + tool, Boolean.TYPE, true, Preferences.Visibility.PROJECT);
            } else {
                preferenceObject_isTabFixedPositionUI_SubTab = new PreferenceObject("isTabFixedPosition_" + tool, Boolean.TYPE, false, Preferences.Visibility.PROJECT);
            }
            preferenceObjectCollection.add(preferenceObject_isTabFixedPositionUI_SubTab);
        }

        return preferenceObjectCollection;
    }

    @Override
    public void loadSettings() {
        loadSettings(null);
    }

    @Override
    public void unloadSettings() {
        sharedParameters.printDebugMessage("removing tab listener on tabs in Repeater and Intruder");
        // remove tab listener on tabs in Repeater and Intruder
        if (subTabsListeners != null && sharedParameters.get_isUILoaded()) {
            subTabsListeners.removeTabListener(sharedParameters.get_rootTabbedPaneUsingMontoya());
        }

        // undo subtabs styles
        sharedParameters.printDebugMessage("undo subtabs styles");
        unsetSubTabsStyle();

    }

    public void loadSettings(BurpUITools.MainTabs currentMainTab) {
        try{
            sharedParameters.printDebugMessage("loadSettings");
            if(updateInProgressLock == null)
                updateInProgressLock = new ReentrantLock();

            if(updateInProgressLock.tryLock(5, TimeUnit.SECONDS)){
                try{
                    for (BurpUITools.MainTabs tool : sharedParameters.subTabSupportedTabs) {
                        if (currentMainTab != null && tool != currentMainTab) {
                            continue;
                        }

                        if (isFirstLoad) {
                            SwingUtilities.invokeLater(() -> {

                                if (!sharedParameters.isSubTabScrollSupportedByDefault) {
                                    // This feature is being supported by Burp Suite 2022.6
                                    if (sharedParameters.preferences.safeGetBooleanSetting("isScrollable_" + tool)) {
                                        try {
                                            // this causes error on Burp start, so we need to run it with a delay
                                            new java.util.Timer().schedule(
                                                    new java.util.TimerTask() {
                                                        @Override
                                                        public void run() {
                                                            var currentToolTabbedPane = sharedParameters.get_toolTabbedPane(tool);
                                                            if(currentToolTabbedPane != null){
                                                                currentToolTabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
                                                            }else{
                                                                sharedParameters.printDebugMessage("Error in getting the current tool tabs: " + tool);
                                                            }

                                                        }
                                                    },
                                                    2000 // 2 seconds-delay to ensure all has been settled!
                                            );
                                        } catch (Exception e) {
                                            sharedParameters.printDebugMessage("Error when applying the isScrollable setting, disabling the setting...");
                                            sharedParameters.preferences.setSetting("isScrollable_" + tool, false);
                                        }
                                    }
                                }

                                if (sharedParameters.preferences.safeGetBooleanSetting("mouseWheelToScroll_" + tool)) {
                                    try {
                                        SubTabsActions.addMouseWheelToJTabbedPane(sharedParameters, tool, sharedParameters.isTabGroupSupportedByDefault);
                                    } catch (Exception e) {
                                        sharedParameters.printDebugMessage("Error when applying the Mouse Wheel setting, disabling the setting...");
                                        sharedParameters.preferences.setSetting("mouseWheelToScroll_" + tool, false);
                                    }
                                }

                                var currentToolTabbedPane = sharedParameters.get_toolTabbedPane(tool);

                                if (sharedParameters.originalSubTabbedPaneUI.get(tool) == null && currentToolTabbedPane != null) {
                                    sharedParameters.originalSubTabbedPaneUI.put(tool, currentToolTabbedPane.getUI());
                                }

                                if (currentToolTabbedPane != null && !sharedParameters.isTabGroupSupportedByDefault) {
                                    currentToolTabbedPane.setUI(SubTabsCustomTabbedPaneUI.getUI(sharedParameters, tool));
                                    SubTabsActions.changeToolTabbedPaneUI_safe(sharedParameters, tool, false);
                                }
                            });
                        }

                        updateAllSubTabContainerHandlersObj(currentMainTab);

                        HashMap<String, TabFeaturesObject> tabFeaturesObjectsHashMap = sharedParameters.preferences.getSetting("TabFeaturesObject_Array_" + tool);

                        boolean isUsingOldSettings = false;
                        if (tabFeaturesObjectsHashMap == null || tabFeaturesObjectsHashMap.size() <= 0) {
                            // backward compatibility as we used the lowercase tool name before version 1.3
                            try {
                                PreferenceObject preferenceObject = new PreferenceObject("TabFeaturesObject_Array_" + tool.toString().toLowerCase(), new TypeToken<HashMap<String, TabFeaturesObject>>() {
                                }.getType(), null, Preferences.Visibility.PROJECT);
                                sharedParameters.preferences.registerSetting(preferenceObject.settingName, preferenceObject.type, preferenceObject.defaultValue, preferenceObject.visibility);
                                tabFeaturesObjectsHashMap = sharedParameters.preferences.getSetting("TabFeaturesObject_Array_" + tool.toString().toLowerCase());
                                sharedParameters.preferences.setSetting("TabFeaturesObject_Array_" + tool.toString().toLowerCase(), null);
                                isUsingOldSettings = true;
                            } catch (Exception e) {
                                //already registered setting
                                sharedParameters.printDebugMessage(e.getMessage());
                                if (sharedParameters.debugLevel == BurpExtensionSharedParameters.DebugLevels.VeryVerbose.getValue())
                                    e.printStackTrace(sharedParameters.stderr);
                            }
                        }

                        if (tabFeaturesObjectsHashMap != null && sharedParameters.supportedTools_SubTabs.get(tool) != null) {
                            sharedParameters.supportedTools_SubTabs.get(tool).putAll(tabFeaturesObjectsHashMap);
                            updateSubTabsUI(tool);
                            // we do this to fix tabs which have been added after Sharpener was unloaded
                            // This is a performance hit on start but a good measure to keep the tab titles unique & stylish
                            saveSettings(tool);

                            /*
                            if (isUsingOldSettings) {
                                saveSettings(tool);
                            }
                            */
                        }

                    }
                    isFirstLoad = false;

                    // Adding MiddleClick / RightClick+Alt to Repeater and Intruder
                    if (sharedParameters.get_rootTabbedPaneUsingMontoya() != null) {
                        sharedParameters.printDebugMessage("Adding MiddleClick / RightClick+Alt to Repeater and Intruder");

                        subTabsListeners = new SubTabsListeners(sharedParameters, mouseEvent -> {
                            SubTabsActions.tabClicked(mouseEvent, sharedParameters);
                        });
                    }
                }finally {
                    updateInProgressLock.unlock();
                }
            }
        }catch (Exception err){
            sharedParameters.printlnError("Lock timeout in SubTabsSettings.loadSettings");
        }
    }

    public void updateSubTabsUI(BurpUITools.MainTabs currentMainTab) {
        try{
            sharedParameters.printDebugMessage("updateSubTabsUI");
            if(updateInProgressLock == null)
                updateInProgressLock = new ReentrantLock();

            if(updateInProgressLock.tryLock(5, TimeUnit.SECONDS)){
                try{
                    if (sharedParameters.supportedTools_SubTabs.get(currentMainTab).size() > 0) {
                        ArrayList<SubTabsContainerHandler> subTabsContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentMainTab);
                        for (SubTabsContainerHandler subTabsContainerHandler : subTabsContainerHandlers) {
                            TabFeaturesObject currentTabFeaturesObject = sharedParameters.supportedTools_SubTabs.get(currentMainTab).get(subTabsContainerHandler.getLowercaseTrimmedTabTitle());
                            if(currentTabFeaturesObject == null){
                                // backward compatibility when titles were case-sensitive and not trimmed
                                currentTabFeaturesObject = sharedParameters.supportedTools_SubTabs.get(currentMainTab).get(subTabsContainerHandler.getTabTitle());
                            }
                            if (currentTabFeaturesObject != null) {
                                subTabsContainerHandler.updateByTabFeaturesObject(currentTabFeaturesObject, true, true);
                            }
                        }
                    }
                }finally {
                    updateInProgressLock.unlock();
                }
            }
        }catch (Exception err){
            sharedParameters.printlnError("Lock timeout in SubTabsSettings.updateSubTabsUI");
        }
    }

    public void updateAllSubTabContainerHandlersObj(BurpUITools.MainTabs currentMainTab) {
        try{
            sharedParameters.printDebugMessage("updateAllSubTabContainerHandlersObj");
            if(updateInProgressLock == null)
                updateInProgressLock = new ReentrantLock();

            if(updateInProgressLock.tryLock(5, TimeUnit.SECONDS)){
                try{
                    for (BurpUITools.MainTabs tool : sharedParameters.subTabSupportedTabs) {
                        if (currentMainTab != null && currentMainTab != tool) {
                            continue;
                        }

                        if (sharedParameters.allSubTabContainerHandlers.get(tool) == null) {
                            // initializing - should be called only once
                            sharedParameters.allSubTabContainerHandlers.put(tool, new ArrayList<>());
                        }

                        var currentToolTabbedPane = sharedParameters.get_toolTabbedPane(tool);
                        if (currentMainTab == null || (currentToolTabbedPane != null && sharedParameters.allSubTabContainerHandlers.get(tool).size() != currentToolTabbedPane.getTabCount())) {
                            // this is not a drag and drop
                            ArrayList<SubTabsContainerHandler> subTabsContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(tool);

                            ArrayList<SubTabsContainerHandler> updatedSubTabsContainerHandlers = new ArrayList<>();
                            for (SubTabsContainerHandler subTabsContainerHandler : subTabsContainerHandlers) {
                                if (subTabsContainerHandler.isValid() || subTabsContainerHandler.isDotDotDotTab()) {
                                    updatedSubTabsContainerHandlers.add(subTabsContainerHandler);
                                }
                            }

                            if (currentToolTabbedPane != null) {
                                for (int subTabIndex = 0; subTabIndex < currentToolTabbedPane.getTabCount(); subTabIndex++) {
                                    SubTabsContainerHandler tempSubTabsContainerHandler = new SubTabsContainerHandler(sharedParameters, currentToolTabbedPane, subTabIndex, true);

                                    if (!updatedSubTabsContainerHandlers.contains(tempSubTabsContainerHandler)) {
                                        // we have a new tab
                                        tempSubTabsContainerHandler.setToDefault(true);
                                        tempSubTabsContainerHandler.addSubTabWatcher();
                                        updatedSubTabsContainerHandlers.add(tempSubTabsContainerHandler);
                                    }
                                }

                                // this for dotdotdot tab!

                                if (!sharedParameters.isTabGroupSupportedByDefault) {
                                    SubTabsContainerHandler tempDotDotDotSubTabsContainerHandler = new SubTabsContainerHandler(sharedParameters, currentToolTabbedPane, currentToolTabbedPane.getTabCount() - 1, true);
                                    if (tempDotDotDotSubTabsContainerHandler != null && !updatedSubTabsContainerHandlers.contains(tempDotDotDotSubTabsContainerHandler)) {
                                        // we have a new tab
                                        tempDotDotDotSubTabsContainerHandler.addSubTabWatcher();
                                        updatedSubTabsContainerHandlers.add(tempDotDotDotSubTabsContainerHandler);
                                    }
                                }
                            }

                            sharedParameters.allSubTabContainerHandlers.get(tool).clear();
                            sharedParameters.allSubTabContainerHandlers.get(tool).addAll(updatedSubTabsContainerHandlers);
                        }

                    }
                }finally {
                    updateInProgressLock.unlock();
                }
            }
        }catch (Exception err){
            sharedParameters.printlnError("Lock timeout in SubTabsSettings.updateAllSubTabContainerHandlersObj");
        }
    }

    private void unsetSubTabsStyle() {
        try{
            sharedParameters.printDebugMessage("unsetSubTabsStyle");
            if(updateInProgressLock == null)
                updateInProgressLock = new ReentrantLock();

            if(updateInProgressLock.tryLock(5, TimeUnit.SECONDS)){
                try{
                    for (BurpUITools.MainTabs tool : sharedParameters.subTabSupportedTabs) {
                        if (!sharedParameters.isSubTabScrollSupportedByDefault) {
                            if (sharedParameters.preferences.safeGetBooleanSetting("isScrollable_" + tool)) {
                                var currentToolTabbedPane = sharedParameters.get_toolTabbedPane(tool);
                                if(currentToolTabbedPane!=null){
                                    currentToolTabbedPane.setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT);
                                }
                            }
                        }

                        if (sharedParameters.preferences.safeGetBooleanSetting("mouseWheelToScroll_" + tool)) {
                            SubTabsActions.removeMouseWheelFromJTabbedPane(sharedParameters, tool, true);
                        }

                        if (sharedParameters.supportedTools_SubTabs.get(tool) != null) {
                            ArrayList<SubTabsContainerHandler> subTabsContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(tool);
                            for (SubTabsContainerHandler subTabsContainerHandler : subTabsContainerHandlers) {
                                if (subTabsContainerHandler.isValid()) {
                                    // Step1 of filter removal
                                    if (sharedParameters.isFiltered(tool))
                                        subTabsContainerHandler.setVisible(true);
                                    subTabsContainerHandler.removeIcon(true);
                                    subTabsContainerHandler.removeSubTabWatcher();
                                    subTabsContainerHandler.setToDefault(true);
                                }
                            }

                            // Step2 of filter and Fixed FTab Position removal
                            if (sharedParameters.originalSubTabbedPaneUI.get(tool) != null) {
                                var currentToolTabbedPane = sharedParameters.get_toolTabbedPane(tool);
                                if(currentToolTabbedPane!=null){
                                    currentToolTabbedPane.updateUI();
                                    currentToolTabbedPane.revalidate();
                                    currentToolTabbedPane.repaint();
                                }
                            }
                        }
                        sharedParameters.allSubTabContainerHandlers.get(tool).clear();
                        sharedParameters.supportedTools_SubTabs.get(tool).clear();
                    }
                }finally {
                    updateInProgressLock.unlock();
                }
            }
        }catch (Exception err){
            sharedParameters.printlnError("Lock timeout in SubTabsSettings.unsetSubTabsStyle");
        }
    }

    public void saveSettings(SubTabsContainerHandler subTabsContainerHandler) {
        sharedParameters.printDebugMessage("saveSettings using SubTabsContainerHandler");
        saveSettings(subTabsContainerHandler.currentToolTab);
    }

    // This saves the setting in the preferences by reading them from SubTabsContainerHandler lists
    public void saveSettings(BurpUITools.MainTabs currentMainTab) {
        try{
            sharedParameters.printDebugMessage("saveSettings using BurpUITools.MainTabs");
            if(updateInProgressLock == null)
                updateInProgressLock = new ReentrantLock();

            if(updateInProgressLock.tryLock(5, TimeUnit.SECONDS)){
                try{
                    for (BurpUITools.MainTabs tool : sharedParameters.subTabSupportedTabs) {
                        if (currentMainTab != null && currentMainTab != tool) {
                            continue;
                        }

                        HashMap<String, TabFeaturesObject> tabFeaturesObjectHashMap = new HashMap<>();

                        ArrayList<SubTabsContainerHandler> subTabsContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(tool);
                        for (SubTabsContainerHandler subTabsContainerHandler : subTabsContainerHandlers) {
                            if (subTabsContainerHandler.isValid()) {
                                subTabsContainerHandler.makeUniqueTitle();
                                if (!subTabsContainerHandler.isDefault() || subTabsContainerHandler.getTitleHistory().length > 1) {
                                    subTabsContainerHandler.setHasChanges(false);
                                    tabFeaturesObjectHashMap.put(subTabsContainerHandler.getLowercaseTrimmedTabTitle(), subTabsContainerHandler.getTabFeaturesObject());
                                }
                            }
                        }

                        // The issue here is that do not know whether there has been a hick up or the user really deleted all the styles
                        // We currently assume is it ok to lose them all if equal or less than 5 tab had the style previously
                        if(!tabFeaturesObjectHashMap.isEmpty() || sharedParameters.supportedTools_SubTabs.get(tool).size() <= 5){
                            sharedParameters.supportedTools_SubTabs.get(tool).clear();
                        }

                        sharedParameters.supportedTools_SubTabs.get(tool).putAll(tabFeaturesObjectHashMap);
                        sharedParameters.preferences.safeSetSetting("TabFeaturesObject_Array_" + tool, tabFeaturesObjectHashMap);
                    }
                }finally {
                    updateInProgressLock.unlock();
                }
            }
        }catch (Exception err){
            sharedParameters.printlnError("Lock timeout in SubTabsSettings.saveSettings");
        }
    }
}
