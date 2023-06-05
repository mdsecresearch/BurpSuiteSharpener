// Burp Suite Extension Name: Sharpener
// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)
// Released initially as open source by MDSec - https://www.mdsec.co.uk
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener

package com.mdsec.burp.sharpener.uiControllers.mainTabs;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.irsdl.burp.generic.BurpUITools;
import com.mdsec.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.objects.PreferenceObject;
import com.irsdl.objects.StandardSettings;

import java.util.ArrayList;
import java.util.Collection;

public class MainTabsSettings extends StandardSettings {
    private MainTabsListeners mainTabsListeners;
    public MainTabsSettings(SharpenerSharedParameters sharedParameters) {
        super(sharedParameters);
        sharedParameters.printDebugMessage("ToolsTabSettings");
    }

    @Override
    public void init() {

    }

    @Override
    public Collection<PreferenceObject> definePreferenceObjectCollection() {
        Collection<PreferenceObject> preferenceObjectCollection = new ArrayList<>();

        for (BurpUITools.MainTabs tool : BurpUITools.MainTabs.values()) {
            PreferenceObject preferenceObject_isUnique_Tab = new PreferenceObject("isUnique_" + tool, Boolean.TYPE, false, Preferences.Visibility.GLOBAL);
            preferenceObjectCollection.add(preferenceObject_isUnique_Tab);
        }

        PreferenceObject preferenceObject_isToolTabPaneScrollable = new PreferenceObject("isToolTabPaneScrollable", Boolean.TYPE, false, Preferences.Visibility.GLOBAL);
        preferenceObjectCollection.add(preferenceObject_isToolTabPaneScrollable);

        PreferenceObject preferenceObject_ToolsThemeName = new PreferenceObject("ToolsThemeName", String.class, "@irsdl", Preferences.Visibility.GLOBAL);
        preferenceObjectCollection.add(preferenceObject_ToolsThemeName);

        PreferenceObject preferenceObject_ToolsIconSize = new PreferenceObject("ToolsIconSize", String.class, "16", Preferences.Visibility.GLOBAL);
        preferenceObjectCollection.add(preferenceObject_ToolsIconSize);

        PreferenceObject preferenceObject_ToolsThemeCustomPath = new PreferenceObject("ToolsThemeCustomPath", String.class, "", Preferences.Visibility.GLOBAL);
        preferenceObjectCollection.add(preferenceObject_ToolsThemeCustomPath);


        return preferenceObjectCollection;
    }

    @Override
    public void loadSettings() {
        sharedParameters.printDebugMessage("loadSettings");
        MainTabsStyleHandler.resetMainTabsStylesFromSettings(sharedParameters);
        // Adding listeners to Main Tool Tabs
        if (sharedParameters.get_rootTabbedPaneUsingMontoya() != null) {
            sharedParameters.printDebugMessage("Adding listeners to main tools' tabs");
            mainTabsListeners = new MainTabsListeners(sharedParameters);
        }
    }

    @Override
    public void unloadSettings() {
        // remove listener for main tools' tabs
        if (mainTabsListeners != null && sharedParameters.get_isUILoaded()) {
            mainTabsListeners.removeTabListener(sharedParameters.get_rootTabbedPaneUsingMontoya());
        }

        sharedParameters.printDebugMessage("undo the Burp main tool tabs");
        // undo the Burp main tool tabs
        MainTabsStyleHandler.unsetAllMainTabsStyles(sharedParameters);

    }
}
