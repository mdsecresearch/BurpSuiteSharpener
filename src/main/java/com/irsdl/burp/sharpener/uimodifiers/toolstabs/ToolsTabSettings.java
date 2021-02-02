// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.uimodifiers.toolstabs;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.burp.sharpener.objects.PreferenceObject;
import com.irsdl.burp.sharpener.objects.StandardSettings;

import java.util.ArrayList;
import java.util.Collection;

public class ToolsTabSettings extends StandardSettings {
    public ToolsTabSettings(SharpenerSharedParameters sharedParameters) {
        super(sharedParameters);
        sharedParameters.printDebugMessages("ToolsTabSettings");
    }

    @Override
    public Collection<PreferenceObject> definePreferenceObjectCollection() {
        Collection<PreferenceObject> preferenceObjectCollection = new ArrayList<>();

        for (BurpUITools.MainTabs tool : BurpUITools.MainTabs.values()) {
            PreferenceObject preferenceObject_isUnique_Tab = new PreferenceObject("isUnique_" + tool.toString(), Boolean.TYPE, false, Preferences.Visibility.GLOBAL);
            preferenceObjectCollection.add(preferenceObject_isUnique_Tab);
        }

        PreferenceObject preferenceObject_isToolTabPaneScrollable = new PreferenceObject("isToolTabPaneScrollable", Boolean.TYPE, false, Preferences.Visibility.GLOBAL);
        preferenceObjectCollection.add(preferenceObject_isToolTabPaneScrollable);

        PreferenceObject preferenceObject_ToolsThemeName = new PreferenceObject("ToolsThemeName", String.class, "office", Preferences.Visibility.GLOBAL);
        preferenceObjectCollection.add(preferenceObject_ToolsThemeName);

        PreferenceObject preferenceObject_ToolsThemeCustomPath = new PreferenceObject("ToolsThemeCustomPath", String.class, "", Preferences.Visibility.GLOBAL);
        preferenceObjectCollection.add(preferenceObject_ToolsThemeCustomPath);


        return preferenceObjectCollection;
    }

    @Override
    public void loadSettings() {
        sharedParameters.printDebugMessages("loadSettings");
        ToolsTabStyleHandler.resetToolTabStylesFromSettings(sharedParameters);
    }
}
