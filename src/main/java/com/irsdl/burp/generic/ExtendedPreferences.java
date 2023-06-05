// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)

package com.irsdl.burp.generic;

import burp.api.montoya.MontoyaApi;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;

public class ExtendedPreferences extends Preferences {
    BurpExtensionSharedParameters sharedParameters;

    public ExtendedPreferences(MontoyaApi montoyaApi, IGsonProvider gsonProvider) {
        super(montoyaApi, gsonProvider);
    }

    public void safeSetSetting(String settingName, Object value) {
        boolean isSaved = false;
        int tryTimes = 0;
        while (!isSaved && tryTimes < 10) {
            tryTimes++;

            if (sharedParameters != null) {
                sharedParameters.printDebugMessage("Try number: " + tryTimes, BurpExtensionSharedParameters.DebugLevels.VerboseAndPrefsRW.getValue());
                sharedParameters.printDebugMessage("Trying to save " + settingName, BurpExtensionSharedParameters.DebugLevels.VerboseAndPrefsRW.getValue());
            }

            try {
                setSetting(settingName, value);

                if (getSetting(settingName).equals(value)) {
                    isSaved = true;
                    if (sharedParameters != null) {
                        sharedParameters.printDebugMessage("This was saved successfully: " + settingName, BurpExtensionSharedParameters.DebugLevels.VerboseAndPrefsRW.getValue());
                    }
                }
            } catch (Exception e) {
                if (sharedParameters != null) {
                    sharedParameters.printDebugMessage("Save error: " + e.getMessage(), BurpExtensionSharedParameters.DebugLevels.VerboseAndPrefsRW.getValue());
                    if (sharedParameters.debugLevel == BurpExtensionSharedParameters.DebugLevels.VeryVerbose.getValue())
                        e.printStackTrace(sharedParameters.stderr);
                }
            }

        }
    }

    public <T> T safeGetSetting(String settingName, T defaultValue) {
        var result = defaultValue;

        try {
            if (sharedParameters != null) {
                sharedParameters.printDebugMessage("Trying to get value of " + settingName + " from settings", BurpExtensionSharedParameters.DebugLevels.VerboseAndPrefsRW.getValue());
            }

            result = getSetting(settingName);
        } catch (Exception e) {
            if (sharedParameters != null) {
                sharedParameters.printDebugMessage("Get error: " + e.getMessage());
                if (sharedParameters.debugLevel == BurpExtensionSharedParameters.DebugLevels.VeryVerbose.getValue())
                    e.printStackTrace(sharedParameters.stderr);
            }
        }
        return result;
    }

    public Object safeGetSetting(String settingName) {
        return safeGetSetting(settingName, null);
    }

    public String safeGetStringSetting(String settingName) {
        return safeGetSetting(settingName, "");
    }

    public boolean safeGetBooleanSetting(String settingName) {
        return safeGetSetting(settingName, false);
    }

    public int safeGetIntSetting(String settingName) {
        return safeGetSetting(settingName, -1);
    }
}
