// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.mdsec.burp.sharpener.capabilities.pwnFox;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.mdsec.burp.sharpener.CustomExtensionSharedParameters;
import com.mdsec.burp.sharpener.objects.PreferenceObject;
import com.mdsec.burp.sharpener.objects.StandardSettings;

import java.util.ArrayList;
import java.util.Collection;

public class PwnFoxSettings extends StandardSettings {
    public PwnFoxSettings(CustomExtensionSharedParameters sharedParameters) {
        super(sharedParameters);
    }

    @Override
    public void init() {

    }

    @Override
    public Collection<PreferenceObject> definePreferenceObjectCollection() {
        Collection<PreferenceObject> preferenceObjectCollection = new ArrayList<>();
        PreferenceObject preferenceObject;
        try {
            preferenceObject = new PreferenceObject("pwnFoxSupportCapability", boolean.class, false, Preferences.Visibility.GLOBAL);
            preferenceObjectCollection.add(preferenceObject);
        } catch (Exception e) {
            //already registered setting
            sharedParameters.printDebugMessage(e.getMessage());
        }

        return preferenceObjectCollection;
    }

    @Override
    public void loadSettings() {

    }

    @Override
    public void unloadSettings() {

    }
}
