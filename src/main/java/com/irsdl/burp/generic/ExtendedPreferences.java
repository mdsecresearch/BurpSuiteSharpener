// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.generic;

import burp.IBurpExtenderCallbacks;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;

public class ExtendedPreferences extends Preferences {
    BurpExtensionSharedParameters sharedParameters;

    public ExtendedPreferences(String extensionIdentifier, IGsonProvider gsonProvider, IBurpExtenderCallbacks callbacks) {
        super(extensionIdentifier, gsonProvider, callbacks);
    }

    public synchronized void safeSetSetting(String settingName, Object value) {
        boolean isSaved = false;
        int tryTimes = 0;
        while (!isSaved && tryTimes < 10) {
            tryTimes++;

            if (sharedParameters != null) {
                sharedParameters.printDebugMessage("Try number: " + tryTimes);
                sharedParameters.printDebugMessage("Trying to save " + settingName);
            }

            try {
                setSetting(settingName, value);

                if (getSetting(settingName).equals(value)) {
                    isSaved = true;
                    if (sharedParameters != null) {
                        sharedParameters.printDebugMessage("This was saved successfully: " + settingName);
                    }
                }
            } catch (Exception e) {
                if (sharedParameters != null) {
                    sharedParameters.printDebugMessage("Save error: " + e.getMessage());
                    if (sharedParameters.debugLevel > 1)
                        e.printStackTrace(sharedParameters.stderr);
                }
            }

        }
    }

    public synchronized <T> T safeGetSetting(String settingName, T defaultValue) {
        var result = defaultValue;

        try {
            if (sharedParameters != null) {
                sharedParameters.printDebugMessage("Trying to get value of " + settingName + " from settings");
            }

            result = getSetting(settingName);
        } catch (Exception e) {
            if (sharedParameters != null) {
                sharedParameters.printDebugMessage("Get error: " + e.getMessage());
                if (sharedParameters.debugLevel > 1)
                    e.printStackTrace(sharedParameters.stderr);
            }
        }
        return result;
    }

    public synchronized Object safeGetSetting(String settingName) {
        return safeGetSetting(settingName, null);
    }

    public synchronized String safeGetStringSetting(String settingName) {
        return safeGetSetting(settingName, "");
    }

    public synchronized boolean safeGetBooleanSetting(String settingName) {
        return safeGetSetting(settingName, false);
    }

    public synchronized int safeGetIntSetting(String settingName) {
        return safeGetSetting(settingName, -1);
    }
}
