// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.actitivities.ui.subTabs;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.reflect.TypeToken;
import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.burp.sharpener.objects.PreferenceObject;
import com.irsdl.burp.sharpener.objects.StandardSettings;
import com.irsdl.burp.sharpener.objects.TabFeaturesObject;

import javax.swing.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;


public class SubTabsSettings extends StandardSettings {

    public String lastSavedImageLocation;
    public boolean isFirstLoad;

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

            PreferenceObject preferenceObject_mouseWheelToScroll_SubTab = new PreferenceObject("mouseWheelToScroll_" + tool, Boolean.TYPE, true, Preferences.Visibility.PROJECT);
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
    public synchronized void loadSettings() {
        loadSettings(null);
    }

    @Override
    public void unloadSettings() {
        sharedParameters.printDebugMessage("removing tab listener on tabs in Repeater and Intruder");
        // remove tab listener on tabs in Repeater and Intruder
        if (subTabsListeners != null && sharedParameters.get_isUILoaded()) {
            subTabsListeners.removeTabListener(sharedParameters.get_rootTabbedPane());
        }

        // undo subtabs styles
        sharedParameters.printDebugMessage("undo subtabs styles");
        unsetSubTabsStyle();

    }

    public synchronized void loadSettings(BurpUITools.MainTabs currentMainTab) {
        sharedParameters.printDebugMessage("loadSettings");

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

                    if (sharedParameters.originalSubTabbedPaneUI.get(tool) == null && sharedParameters.get_toolTabbedPane(tool) != null)
                        sharedParameters.originalSubTabbedPaneUI.put(tool, sharedParameters.get_toolTabbedPane(tool).getUI());

                    if (sharedParameters.originalSubTabbedPaneUI.get(tool) == null &&
                            sharedParameters.get_toolTabbedPane(tool) != null) {
                        sharedParameters.originalSubTabbedPaneUI.put(tool,
                                sharedParameters.get_toolTabbedPane(tool).getUI());
                    }

                    if (sharedParameters.get_toolTabbedPane(tool) != null && !sharedParameters.isTabGroupSupportedByDefault) {
                        sharedParameters.get_toolTabbedPane(tool).setUI(SubTabsCustomTabbedPaneUI.getUI(sharedParameters, tool));
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
                    if (sharedParameters.debugLevel > 1)
                        e.printStackTrace(sharedParameters.stderr);
                }
            }

            if (tabFeaturesObjectsHashMap != null && sharedParameters.supportedTools_SubTabs.get(tool) != null) {
                sharedParameters.supportedTools_SubTabs.get(tool).putAll(tabFeaturesObjectsHashMap);
                updateSubTabsUI(tool);
                if (isUsingOldSettings) {
                    saveSettings(tool);
                }
            }

        }
        isFirstLoad = false;

        // Adding MiddleClick / RightClick+Alt to Repeater and Intruder
        if (sharedParameters.get_rootTabbedPane() != null) {
            sharedParameters.printDebugMessage("Adding MiddleClick / RightClick+Alt to Repeater and Intruder");

            subTabsListeners = new SubTabsListeners(sharedParameters, mouseEvent -> {
                SubTabsActions.tabClicked(mouseEvent, sharedParameters);
            });
        }

    }

    public synchronized void updateSubTabsUI(BurpUITools.MainTabs currentMainTab) {
        if (sharedParameters.supportedTools_SubTabs.get(currentMainTab).size() > 0) {
            ArrayList<SubTabsContainerHandler> subTabsContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentMainTab);
            for (SubTabsContainerHandler subTabsContainerHandler : subTabsContainerHandlers) {
                TabFeaturesObject currentTabFeaturesObject = sharedParameters.supportedTools_SubTabs.get(currentMainTab).get(subTabsContainerHandler.getTabTitle());
                if (currentTabFeaturesObject != null) {
                    subTabsContainerHandler.updateByTabFeaturesObject(currentTabFeaturesObject, true, true);
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
                ArrayList<SubTabsContainerHandler> subTabsContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(tool);

                ArrayList<SubTabsContainerHandler> updatedSubTabsContainerHandlers = new ArrayList<>();
                for (SubTabsContainerHandler subTabsContainerHandler : subTabsContainerHandlers) {
                    if (subTabsContainerHandler.isValid() || subTabsContainerHandler.isDotDotDotTab()) {
                        updatedSubTabsContainerHandlers.add(subTabsContainerHandler);
                    }
                }

                JTabbedPane subTabbedPane = sharedParameters.get_toolTabbedPane(tool);
                if (subTabbedPane != null) {
                    for (int subTabIndex = 0; subTabIndex < subTabbedPane.getTabCount(); subTabIndex++) {
                        SubTabsContainerHandler tempSubTabsContainerHandler = new SubTabsContainerHandler(sharedParameters, subTabbedPane, subTabIndex, true);

                        if (!updatedSubTabsContainerHandlers.contains(tempSubTabsContainerHandler)) {
                            // we have a new tab
                            tempSubTabsContainerHandler.setToDefault(true);
                            tempSubTabsContainerHandler.addSubTabWatcher();
                            updatedSubTabsContainerHandlers.add(tempSubTabsContainerHandler);
                        }
                    }

                    // this for dotdotdot tab!

                    if (!sharedParameters.isTabGroupSupportedByDefault) {
                        SubTabsContainerHandler tempDotDotDotSubTabsContainerHandler = new SubTabsContainerHandler(sharedParameters, subTabbedPane, subTabbedPane.getTabCount() - 1, true);
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

    }

    private synchronized void unsetSubTabsStyle() {
        sharedParameters.printDebugMessage("unsetSubTabsStyle");
        for (BurpUITools.MainTabs tool : sharedParameters.subTabSupportedTabs) {
            if (!sharedParameters.isSubTabScrollSupportedByDefault) {
                if (sharedParameters.preferences.safeGetBooleanSetting("isScrollable_" + tool)) {
                    sharedParameters.get_toolTabbedPane(tool).setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT);
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
                    sharedParameters.get_toolTabbedPane(tool).updateUI();
                    sharedParameters.get_toolTabbedPane(tool).revalidate();
                    sharedParameters.get_toolTabbedPane(tool).repaint();
                }
            }
            sharedParameters.allSubTabContainerHandlers.get(tool).clear();
            sharedParameters.supportedTools_SubTabs.get(tool).clear();
        }
    }

    public synchronized void prepareAndSaveSettings(SubTabsContainerHandler subTabsContainerHandler) {
        sharedParameters.printDebugMessage("prepareAndSaveSettings");
        subTabsContainerHandler.setHasChanges(false);
        // save the changed tabs ...
        if (!subTabsContainerHandler.isCurrentTitleUnique(false)) {
            // We need to rename its title to become unique
            String initTitle = subTabsContainerHandler.getTabTitle();
            int i = 1;
            String newTitle = "";
            while (newTitle.isEmpty() || !subTabsContainerHandler.isNewTitleUnique(newTitle, false)) {
                // we need to add a number to the title to make it a unique title
                i++;
                newTitle = initTitle + " (#" + i + ")";
            }

            TabFeaturesObject originalFO = sharedParameters.supportedTools_SubTabs.get(subTabsContainerHandler.currentToolTab).get(initTitle);
            if (originalFO != null) {
                // the original item has special style, so we need to copy it
                originalFO.title = newTitle; // we will fix the supportedTools_SubTabs parameter in saveSettings()
                subTabsContainerHandler.updateByTabFeaturesObject(originalFO, false, true);
            } else {
                // the original item has no style
                subTabsContainerHandler.setTabTitle(newTitle, true);
            }
        }

        // we use the title as the hashmap key
        saveSettings(subTabsContainerHandler.currentToolTab);
    }

    public synchronized void saveSettings(BurpUITools.MainTabs currentMainTab) {
        sharedParameters.printDebugMessage("saveSettings");

        for (BurpUITools.MainTabs tool : sharedParameters.subTabSupportedTabs) {
            if (currentMainTab != null && currentMainTab != tool) {
                continue;
            }

            sharedParameters.supportedTools_SubTabs.get(tool).clear();
            HashMap<String, TabFeaturesObject> tabFeaturesObjectHashMap = new HashMap<>();

            ArrayList<SubTabsContainerHandler> subTabsContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(tool);
            for (SubTabsContainerHandler subTabsContainerHandler : subTabsContainerHandlers) {
                if (subTabsContainerHandler.isValid() && (!subTabsContainerHandler.isDefault() || subTabsContainerHandler.getTitleHistory().length > 1)) {
                    subTabsContainerHandler.setHasChanges(false);
                    tabFeaturesObjectHashMap.put(subTabsContainerHandler.getTabTitle(), subTabsContainerHandler.getTabFeaturesObject());
                }
            }
            sharedParameters.supportedTools_SubTabs.get(tool).putAll(tabFeaturesObjectHashMap);
            sharedParameters.preferences.safeSetSetting("TabFeaturesObject_Array_" + tool, tabFeaturesObjectHashMap);
        }
    }
}
