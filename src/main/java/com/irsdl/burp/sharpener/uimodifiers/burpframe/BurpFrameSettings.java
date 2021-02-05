// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.uimodifiers.burpframe;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.irsdl.burp.generic.BurpTitleAndIcon;
import com.irsdl.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.burp.sharpener.objects.PreferenceObject;
import com.irsdl.burp.sharpener.objects.StandardSettings;

import java.util.ArrayList;
import java.util.Collection;

public class BurpFrameSettings extends StandardSettings {

    public BurpFrameSettings(SharpenerSharedParameters sharedParameters) {
        super(sharedParameters);
        sharedParameters.printDebugMessages("BurpFrameSettings");
    }

    @Override
    public Collection<PreferenceObject> definePreferenceObjectCollection() {
        Collection<PreferenceObject> preferenceObjectCollection = new ArrayList<>();

        String[] projectStringSettingNames = {"BurpTitle", "BurpIconCustomPath"};
        for (String settingName : projectStringSettingNames) {
            try {
                PreferenceObject preferenceObject = new PreferenceObject(settingName, String.class, "", Preferences.Visibility.PROJECT);
                preferenceObjectCollection.add(preferenceObject);
            } catch (Exception e) {
                //already registered setting
                sharedParameters.printDebugMessages(e.getMessage());
            }
        }
        return preferenceObjectCollection;
    }

    @Override
    public synchronized void loadSettings() {
        sharedParameters.printDebugMessages("loadSettings");

        String newTitle = sharedParameters.preferences.getSetting("BurpTitle");
        if (!newTitle.isEmpty()) {
            BurpTitleAndIcon.setTitle(sharedParameters, newTitle);
        }

        String newIconPath = sharedParameters.preferences.getSetting("BurpIconCustomPath");
        if (!newIconPath.isEmpty()) {
            BurpTitleAndIcon.setIcon(sharedParameters, newIconPath);
        }
    }
}
