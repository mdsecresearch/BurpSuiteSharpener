// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.objects;

import com.irsdl.burp.sharpener.SharpenerSharedParameters;

import java.util.Collection;

public abstract class StandardSettings {
    private final Collection<PreferenceObject> _preferenceObjectCollection;
    public SharpenerSharedParameters sharedParameters;

    public StandardSettings(SharpenerSharedParameters sharedParameters) {
        this.sharedParameters = sharedParameters;
        init();
        this._preferenceObjectCollection = definePreferenceObjectCollection();
        registerSettings();
        loadSettings();
    }

    abstract public void init();

    abstract public Collection<PreferenceObject> definePreferenceObjectCollection();

    abstract public void loadSettings();

    public Collection<PreferenceObject> get_preferenceObjectCollection() {
        return _preferenceObjectCollection;
    }

    public synchronized void registerSettings() {
        if (_preferenceObjectCollection == null)
            return;

        for (PreferenceObject preferenceObject : _preferenceObjectCollection) {
            try {
                sharedParameters.preferences.registerSetting(preferenceObject.settingName, preferenceObject.type, preferenceObject.defaultValue, preferenceObject.visibility);
            } catch (Exception e) {
                //already registered setting
                sharedParameters.printDebugMessage(e.getMessage());
                if(sharedParameters.debugLevel > 1)
                    e.printStackTrace(sharedParameters.stderr);
            }
        }
    }

    public synchronized void saveSettings(String settingName, Object value) {
        boolean isSaved = false;
        int tryTimes = 0;
        while (!isSaved && tryTimes < 10) {
            tryTimes++;

            sharedParameters.printDebugMessage("Try number: " + tryTimes);
            sharedParameters.printDebugMessage("Trying to save " + settingName);


            if (value != null) {
                try {
                    sharedParameters.preferences.resetSetting(settingName); // to resolve a bug in saving in sitemap when values are similar
                } catch (Exception e) {
                    sharedParameters.printDebugMessage("Was not possible to reset the value: " + e.getMessage());
                    if(sharedParameters.debugLevel > 1)
                        e.printStackTrace(sharedParameters.stderr);
                }

                /*
                // As Corey's preferences.resetSetting has a new patch, we are going to give it the responsibility to clear everything above
                try {
                    sharedParameters.preferences.setSetting(settingName, null);// to resolve a bug in saving in sitemap when values are similar
                } catch (Exception e1) {
                    if (sharedParameters.isDebug) {
                        sharedParameters.printlnError("Was not possible to set the null value: " + e1.getMessage());
                    }
                    try {
                        sharedParameters.preferences.setSetting(settingName, "");// to resolve a bug in saving in sitemap when values are similar
                    } catch (Exception e2) {
                        if (sharedParameters.isDebug) {
                            sharedParameters.printlnError("Was not possible to set the empty value: " + e2.getMessage());
                        }
                    }
                }
                */
            }

            try {
                sharedParameters.preferences.setSetting(settingName, value);

                if (sharedParameters.preferences.getSetting(settingName).equals(value)) {
                    isSaved = true;
                    sharedParameters.printDebugMessage("This was saved successfully: " + settingName);
                }
            } catch (Exception e) {
                sharedParameters.printDebugMessage("Save error: " + e.getMessage());
                if(sharedParameters.debugLevel > 1)
                    e.printStackTrace(sharedParameters.stderr);
            }

        }


    }

    public synchronized void resetSettings() {
        if (_preferenceObjectCollection == null)
            return;

        for (PreferenceObject preferenceObject : _preferenceObjectCollection) {
            try {
                // sharedParameters.preferences.resetSetting(preferenceObject.settingName); // there is a bug in the library so we can't use this for now
                sharedParameters.preferences.setSetting(preferenceObject.settingName, null);
            } catch (Exception e) {
                sharedParameters.printDebugMessage(e.getMessage());
                if(sharedParameters.debugLevel > 1)
                    e.printStackTrace(sharedParameters.stderr);
            }
        }
    }
}
