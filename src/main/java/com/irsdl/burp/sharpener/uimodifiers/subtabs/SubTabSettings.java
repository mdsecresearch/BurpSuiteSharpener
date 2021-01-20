// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.uimodifiers.subtabs;

import com.coreyd97.BurpExtenderUtilities.Preferences;
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

    public SubTabSettings(SharpenerSharedParameters sharedParameters) {
        super(sharedParameters);
        if(sharedParameters.isDebug)
            sharedParameters.printlnOutput("SubTabSettings");
    }

    @Override
    public Collection<PreferenceObject> definePreferenceObjectCollection() {
        Collection<PreferenceObject> preferenceObjectCollection = new ArrayList<>();
        for (BurpUITools.MainTabs tool : sharedParameters.subTabWatcherSupportedTabs) {
            PreferenceObject preferenceObject = new PreferenceObject("TabFeaturesObject_Array_" + tool.toString().toLowerCase(), new TypeToken<HashMap<String, TabFeaturesObject>>() {
            }.getType(), null, Preferences.Visibility.PROJECT);
            preferenceObjectCollection.add(preferenceObject);
        }

        return preferenceObjectCollection;
    }

    @Override
    public void loadSettings() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new Thread(() -> {
                    if(sharedParameters.isDebug)
                        sharedParameters.printlnOutput("loadSettings");
                    updateAllSubTabContainerHandlersObj();
                    for (BurpUITools.MainTabs tool : sharedParameters.subTabWatcherSupportedTabs) {
                        HashMap<String, TabFeaturesObject> tabFeaturesObjectsHashMap = sharedParameters.preferences.getSetting("TabFeaturesObject_Array_" + tool.toString().toLowerCase());
                        if (tabFeaturesObjectsHashMap != null && sharedParameters.supportedTools_SubTabs.get(tool) != null) {
                            sharedParameters.supportedTools_SubTabs.get(tool).putAll(tabFeaturesObjectsHashMap);
                            ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(tool);
                            for (SubTabContainerHandler subTabContainerHandler : subTabContainerHandlers) {
                                TabFeaturesObject currentTabFeaturesObject = sharedParameters.supportedTools_SubTabs.get(tool).get(subTabContainerHandler.getTabTitle());
                                if (currentTabFeaturesObject != null) {
                                    subTabContainerHandler.updateByTabFeaturesObject(currentTabFeaturesObject);
                                }
                            }
                        }
                    }
                }).start();
            }
        });
    }

    public void updateAllSubTabContainerHandlersObj() {
        if(sharedParameters.isDebug)
            sharedParameters.printlnOutput("updateAllSubTabContainerHandlersObj");
        for (BurpUITools.MainTabs tool : sharedParameters.subTabWatcherSupportedTabs) {
            if (sharedParameters.allSubTabContainerHandlers.get(tool) == null) {
                // initializing - should be called only once
                sharedParameters.allSubTabContainerHandlers.put(tool, new ArrayList<>());
            }

            ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(tool);

            ArrayList<SubTabContainerHandler> updatedSubTabContainerHandlers = new ArrayList<>();
            for (SubTabContainerHandler subTabContainerHandler : subTabContainerHandlers) {
                if (subTabContainerHandler.isValid()) {
                    updatedSubTabContainerHandlers.add(subTabContainerHandler);
                }
            }

            JTabbedPane subTabbedPane = sharedParameters.get_toolTabbedPane(tool);
            if (subTabbedPane != null) {
                for (Component subTabComponent : subTabbedPane.getComponents()) {
                    int subTabIndex = subTabbedPane.indexOfComponent(subTabComponent);
                    if (subTabIndex == -1)
                        continue;

                    SubTabContainerHandler tempSubTabContainerHandler = new SubTabContainerHandler(sharedParameters, subTabbedPane, subTabIndex);
                    if (!updatedSubTabContainerHandlers.contains(tempSubTabContainerHandler)) {
                        // we have a new tab
                        updatedSubTabContainerHandlers.add(tempSubTabContainerHandler);
                    }
                }
            }
            sharedParameters.allSubTabContainerHandlers.get(tool).clear();
            sharedParameters.allSubTabContainerHandlers.get(tool).addAll(updatedSubTabContainerHandlers);
        }

    }

    public void unsetSubTabsStyle() {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new Thread(() -> {
                    if(sharedParameters.isDebug)
                        sharedParameters.printlnOutput("unsetSubTabsStyle");
                    for (BurpUITools.MainTabs tool : sharedParameters.subTabWatcherSupportedTabs) {
                        if (sharedParameters.supportedTools_SubTabs.get(tool) != null) {
                            ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(tool);
                            for (SubTabContainerHandler subTabContainerHandler : subTabContainerHandlers) {
                                if (subTabContainerHandler.isValid()) {
                                    subTabContainerHandler.setToDefault();
                                    subTabContainerHandler.removeSubTabWatcher();
                                    subTabContainerHandler = null;
                                }
                            }
                        }
                        sharedParameters.allSubTabContainerHandlers.get(tool).clear();
                        sharedParameters.supportedTools_SubTabs.get(tool).clear();
                    }
                }).start();
            }
        });
    }

    public void prepareAndSaveSettings(SubTabContainerHandler subTabContainerHandler) {
        if(sharedParameters.isDebug)
            sharedParameters.printlnOutput("prepareAndSaveSettings");

        // save the changed tabs ...
        if (!subTabContainerHandler.isCurrentTitleUnique()) {
            // We need to rename its title to become unique
            String initTitle = subTabContainerHandler.getTabTitle();
            int i = 1;
            String newTitle = "";
            while (newTitle.isEmpty() || !subTabContainerHandler.isNewTitleUnique(newTitle)) {
                // we need to add a number to the title to make it a unique title
                i++;
                newTitle = initTitle + " #" + i;
            }
            //subTabContainerHandler.setTabTitle(newTitle);
            TabFeaturesObject originalFO = sharedParameters.supportedTools_SubTabs.get(subTabContainerHandler.currentToolTab).get(initTitle);
            if (originalFO != null) {
                // the original item has special style so we need to copy it
                originalFO.title = newTitle; // we will fix the supportedTools_SubTabs parameter in saveSettings()
                subTabContainerHandler.updateByTabFeaturesObject(originalFO);
            } else {
                // the original item has no style
                subTabContainerHandler.setTabTitle(newTitle);
            }
        }

        // we use the title as the hashmap key
        saveSettings();
    }

    public void saveSettings() {
        if(sharedParameters.isDebug)
            sharedParameters.printlnOutput("saveSettings");

        for (BurpUITools.MainTabs tool : sharedParameters.subTabWatcherSupportedTabs) {
            sharedParameters.supportedTools_SubTabs.get(tool).clear();
            HashMap<String, TabFeaturesObject> tabFeaturesObjectHashMap = new HashMap<>();

            ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(tool);
            for (SubTabContainerHandler subTabContainerHandler : subTabContainerHandlers) {
                if (subTabContainerHandler.isValid() && !subTabContainerHandler.isDefault()) {
                    tabFeaturesObjectHashMap.put(subTabContainerHandler.getTabTitle(), subTabContainerHandler.getTabFeaturesObject());
                }
            }
            sharedParameters.supportedTools_SubTabs.get(tool).putAll(tabFeaturesObjectHashMap);
            sharedParameters.allSettings.saveSettings("TabFeaturesObject_Array_" + tool.toString().toLowerCase(), tabFeaturesObjectHashMap);

        }
    }
}
