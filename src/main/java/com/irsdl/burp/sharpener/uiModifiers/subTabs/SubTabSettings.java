// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.uiModifiers.subTabs;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.formdev.flatlaf.ui.FlatTabbedPaneUI;
import com.google.gson.reflect.TypeToken;
import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.burp.sharpener.objects.PreferenceObject;
import com.irsdl.burp.sharpener.objects.StandardSettings;
import com.irsdl.burp.sharpener.objects.TabFeaturesObject;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;


public class SubTabSettings extends StandardSettings {

    public String lastSavedImageLocation;
    public boolean isFirstLoad;

    public SubTabSettings(SharpenerSharedParameters sharedParameters) {
        super(sharedParameters);
        sharedParameters.printDebugMessage("SubTabSettings");
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

            PreferenceObject preferenceObject_isScrollable_Tab = new PreferenceObject("isScrollable_" + tool, Boolean.TYPE, false, Preferences.Visibility.GLOBAL);
            preferenceObjectCollection.add(preferenceObject_isScrollable_Tab);

            PreferenceObject preferenceObject_mouseWheelToScroll_Tab = new PreferenceObject("mouseWheelToScroll_" + tool, Boolean.TYPE, true, Preferences.Visibility.GLOBAL);
            preferenceObjectCollection.add(preferenceObject_mouseWheelToScroll_Tab);

            PreferenceObject preferenceObject_minimizeSize_Tab = new PreferenceObject("minimizeSize_" + tool, Boolean.TYPE, false, Preferences.Visibility.GLOBAL);
            preferenceObjectCollection.add(preferenceObject_minimizeSize_Tab);

            PreferenceObject preferenceObject_isTabFixedPositionUI_Tab;
            if (sharedParameters.burpMajorVersion > 2022 || (sharedParameters.burpMajorVersion == 2022 && sharedParameters.burpMinorVersion >= 3)) {
                preferenceObject_isTabFixedPositionUI_Tab = new PreferenceObject("isTabFixedPosition_" + tool, Boolean.TYPE, true, Preferences.Visibility.GLOBAL);
            }else{
                preferenceObject_isTabFixedPositionUI_Tab = new PreferenceObject("isTabFixedPosition_" + tool, Boolean.TYPE, false, Preferences.Visibility.GLOBAL);
            }
            preferenceObjectCollection.add(preferenceObject_isTabFixedPositionUI_Tab);
        }

        return preferenceObjectCollection;
    }

    @Override
    public synchronized void loadSettings() {
        loadSettings(null);
    }

    public synchronized void loadSettings(BurpUITools.MainTabs currentMainTab) {
        sharedParameters.printDebugMessage("loadSettings");

        for (BurpUITools.MainTabs tool : sharedParameters.subTabSupportedTabs) {
            if (currentMainTab != null && tool != currentMainTab) {
                continue;
            }

            if (isFirstLoad) {
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        new Thread(() -> {
                            if ((boolean) sharedParameters.preferences.getSetting("isScrollable_" + tool)) {
                                try{
                                    // this causes error on Burp start so we need to run it with a delay
                                    new java.util.Timer().schedule(
                                            new java.util.TimerTask() {
                                                @Override
                                                public void run() {
                                                    sharedParameters.get_toolTabbedPane(tool).setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
                                                }
                                            },
                                            2000 // 2 seconds-delay to ensure all has been settled!
                                    );
                                }catch(Exception e){
                                    sharedParameters.printDebugMessage("Error when applying the isScrollable setting, disabling the setting...");
                                    sharedParameters.preferences.setSetting("isScrollable_" + tool,false);
                                }
                            }

                            if ((boolean) sharedParameters.preferences.getSetting("mouseWheelToScroll_" + tool)) {
                                try{
                                    SubTabActions.addMouseWheelToJTabbedPane(sharedParameters, tool, false);
                                }catch(Exception e){
                                    sharedParameters.printDebugMessage("Error when applying the Mouse Wheel setting, disabling the setting...");
                                    sharedParameters.preferences.setSetting("mouseWheelToScroll_" + tool,false);
                                }
                            }

                            if(sharedParameters.originalSubTabbedPaneUI.get(tool) == null && sharedParameters.get_toolTabbedPane(tool) != null)
                                sharedParameters.originalSubTabbedPaneUI.put(tool,sharedParameters.get_toolTabbedPane(tool).getUI());

                            if (sharedParameters.originalSubTabbedPaneUI.get(tool) == null &&
                                    sharedParameters.get_toolTabbedPane(tool) != null) {
                                sharedParameters.originalSubTabbedPaneUI.put(tool,
                                        sharedParameters.get_toolTabbedPane(tool).getUI());
                            }

                            if(sharedParameters.get_toolTabbedPane(tool)!=null)
                                sharedParameters.get_toolTabbedPane(tool).setUI(SubTabCustomTabbedPaneUI.getUI(sharedParameters, tool));

                        }).start();
                    }
                });
            }

            updateAllSubTabContainerHandlersObj(currentMainTab);

            HashMap<String, TabFeaturesObject> tabFeaturesObjectsHashMap = sharedParameters.preferences.getSetting("TabFeaturesObject_Array_" + tool);

            boolean isUsingOldSettings = false;
            if(tabFeaturesObjectsHashMap ==null || tabFeaturesObjectsHashMap.size() <= 0){
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
                    if(sharedParameters.debugLevel > 1)
                        e.printStackTrace(sharedParameters.stderr);
                }
            }

            if (tabFeaturesObjectsHashMap != null && sharedParameters.supportedTools_SubTabs.get(tool) != null) {
                sharedParameters.supportedTools_SubTabs.get(tool).putAll(tabFeaturesObjectsHashMap);
                updateSubTabsUI(tool);
                if(isUsingOldSettings){
                    saveSettings(tool);
                }
            }

        }
        isFirstLoad = false;
    }

    public synchronized void updateSubTabsUI(BurpUITools.MainTabs currentMainTab) {
        if(sharedParameters.supportedTools_SubTabs.get(currentMainTab).size() > 0){
            ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentMainTab);
            for (SubTabContainerHandler subTabContainerHandler : subTabContainerHandlers) {
                TabFeaturesObject currentTabFeaturesObject = sharedParameters.supportedTools_SubTabs.get(currentMainTab).get(subTabContainerHandler.getTabTitle());
                if (currentTabFeaturesObject != null) {
                    subTabContainerHandler.updateByTabFeaturesObject(currentTabFeaturesObject, true, true);
                }
            }
        }
    }

    public synchronized void updateAllSubTabContainerHandlersObj(BurpUITools.MainTabs currentMainTab) {
        sharedParameters.printDebugMessage("updateAllSubTabContainerHandlersObj");

        for (BurpUITools.MainTabs tool : sharedParameters.subTabSupportedTabs) {
            if (currentMainTab != null && currentMainTab != tool) {
                continue;
            }

            if (sharedParameters.allSubTabContainerHandlers.get(tool) == null) {
                // initializing - should be called only once
                sharedParameters.allSubTabContainerHandlers.put(tool, new ArrayList<>());
            }

            if (currentMainTab == null || sharedParameters.allSubTabContainerHandlers.get(tool).size() != sharedParameters.get_toolTabbedPane(tool).getTabCount()) {
                // this is not a drag and drop
                ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(tool);

                ArrayList<SubTabContainerHandler> updatedSubTabContainerHandlers = new ArrayList<>();
                for (SubTabContainerHandler subTabContainerHandler : subTabContainerHandlers) {
                    if (subTabContainerHandler.isValid() || subTabContainerHandler.isDotDotDotTab()) {
                        updatedSubTabContainerHandlers.add(subTabContainerHandler);
                    }
                }

                JTabbedPane subTabbedPane = sharedParameters.get_toolTabbedPane(tool);
                if (subTabbedPane != null) {
                    for (Component subTabComponent : subTabbedPane.getComponents()) {
                        int subTabIndex = subTabbedPane.indexOfComponent(subTabComponent);
                        if (subTabIndex == -1)
                            continue;

                        SubTabContainerHandler tempSubTabContainerHandler = new SubTabContainerHandler(sharedParameters, subTabbedPane, subTabIndex, true);
                        if (!updatedSubTabContainerHandlers.contains(tempSubTabContainerHandler)) {
                            // we have a new tab
                            tempSubTabContainerHandler.setToDefault(true);
                            tempSubTabContainerHandler.addSubTabWatcher();
                            updatedSubTabContainerHandlers.add(tempSubTabContainerHandler);
                        }
                    }
                    // this for dotdotdot tab!
                    SubTabContainerHandler tempDotDotDotSubTabContainerHandler = new SubTabContainerHandler(sharedParameters, subTabbedPane, subTabbedPane.getTabCount()-1, true);
                    if (tempDotDotDotSubTabContainerHandler != null && !updatedSubTabContainerHandlers.contains(tempDotDotDotSubTabContainerHandler)) {
                        // we have a new tab
                        tempDotDotDotSubTabContainerHandler.addSubTabWatcher();
                        updatedSubTabContainerHandlers.add(tempDotDotDotSubTabContainerHandler);
                    }
                }

                sharedParameters.allSubTabContainerHandlers.get(tool).clear();
                sharedParameters.allSubTabContainerHandlers.get(tool).addAll(updatedSubTabContainerHandlers);
            }

        }

    }

    public synchronized void unsetSubTabsStyle() {
        sharedParameters.printDebugMessage("unsetSubTabsStyle");
        for (BurpUITools.MainTabs tool : sharedParameters.subTabSupportedTabs) {
            if ((boolean) sharedParameters.preferences.getSetting("isScrollable_" + tool)) {
                sharedParameters.get_toolTabbedPane(tool).setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT);
            }

            if ((boolean) sharedParameters.preferences.getSetting("mouseWheelToScroll_" + tool)) {
                SubTabActions.removeMouseWheelFromJTabbedPane(sharedParameters,tool, true);
            }

            if (sharedParameters.supportedTools_SubTabs.get(tool) != null) {
                ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(tool);
                for (SubTabContainerHandler subTabContainerHandler : subTabContainerHandlers) {
                    if (subTabContainerHandler.isValid()) {
                        // Step1 of filter removal
                        if(sharedParameters.isFiltered(tool))
                            subTabContainerHandler.setVisible(true);
                        subTabContainerHandler.removeIcon(true);
                        subTabContainerHandler.removeSubTabWatcher();
                        subTabContainerHandler.setToDefault(true);
                    }
                }

                // Step2 of filter and Fixed Tab Position removal
                if(sharedParameters.originalSubTabbedPaneUI.get(tool) != null) {
                    //sharedParameters.get_toolTabbedPane(tool).setUI(sharedParameters.get_toolTabbedPane(tool).getUI()); // replaced by updateUI()
                    sharedParameters.get_toolTabbedPane(tool).updateUI();
                    sharedParameters.get_toolTabbedPane(tool).revalidate();
                    sharedParameters.get_toolTabbedPane(tool).repaint();
                }
            }
            sharedParameters.allSubTabContainerHandlers.get(tool).clear();
            sharedParameters.supportedTools_SubTabs.get(tool).clear();
        }
    }

    public synchronized void prepareAndSaveSettings(SubTabContainerHandler subTabContainerHandler) {
        sharedParameters.printDebugMessage("prepareAndSaveSettings");
        subTabContainerHandler.setHasChanges(false);
        // save the changed tabs ...
        if (!subTabContainerHandler.isCurrentTitleUnique(false)) {
            // We need to rename its title to become unique
            String initTitle = subTabContainerHandler.getTabTitle();
            int i = 1;
            String newTitle = "";
            while (newTitle.isEmpty() || !subTabContainerHandler.isNewTitleUnique(newTitle, false)) {
                // we need to add a number to the title to make it a unique title
                i++;
                newTitle = initTitle + " (#" + i + ")";
            }
            //subTabContainerHandler.setTabTitle(newTitle);
            TabFeaturesObject originalFO = sharedParameters.supportedTools_SubTabs.get(subTabContainerHandler.currentToolTab).get(initTitle);
            if (originalFO != null) {
                // the original item has special style, so we need to copy it
                originalFO.title = newTitle; // we will fix the supportedTools_SubTabs parameter in saveSettings()
                subTabContainerHandler.updateByTabFeaturesObject(originalFO, false, true);
            } else {
                // the original item has no style
                subTabContainerHandler.setTabTitle(newTitle, true);
            }
        }

        // we use the title as the hashmap key
        saveSettings(subTabContainerHandler.currentToolTab);
    }

    public synchronized void saveSettings(BurpUITools.MainTabs currentMainTab) {
        sharedParameters.printDebugMessage("saveSettings");

        for (BurpUITools.MainTabs tool : sharedParameters.subTabSupportedTabs) {
            if (currentMainTab != null && currentMainTab != tool) {
                continue;
            }

            sharedParameters.supportedTools_SubTabs.get(tool).clear();
            HashMap<String, TabFeaturesObject> tabFeaturesObjectHashMap = new HashMap<>();

            ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(tool);
            for (SubTabContainerHandler subTabContainerHandler : subTabContainerHandlers) {
                if (subTabContainerHandler.isValid() && (!subTabContainerHandler.isDefault() || subTabContainerHandler.getTitleHistory().length > 1)) {
                    subTabContainerHandler.setHasChanges(false);
                    tabFeaturesObjectHashMap.put(subTabContainerHandler.getTabTitle(), subTabContainerHandler.getTabFeaturesObject());
                }
            }
            sharedParameters.supportedTools_SubTabs.get(tool).putAll(tabFeaturesObjectHashMap);
            sharedParameters.allSettings.saveSettings("TabFeaturesObject_Array_" + tool, tabFeaturesObjectHashMap);
        }
    }
}
