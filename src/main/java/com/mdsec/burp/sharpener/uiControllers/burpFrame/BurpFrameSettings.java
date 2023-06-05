// Burp Suite Extension Name: Sharpener
// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)
// Released initially as open source by MDSec - https://www.mdsec.co.uk
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener

package com.mdsec.burp.sharpener.uiControllers.burpFrame;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.irsdl.burp.generic.BurpTitleAndIcon;
import com.mdsec.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.objects.PreferenceObject;
import com.irsdl.objects.StandardSettings;

import java.awt.*;
import java.util.ArrayList;
import java.util.Collection;

public class BurpFrameSettings extends StandardSettings {

    private BurpFrameListeners burpFrameListeners;

    public BurpFrameSettings(SharpenerSharedParameters sharedParameters) {
        super(sharedParameters);
        sharedParameters.printDebugMessage("BurpFrameSettings");
    }

    @Override
    public void init() {

    }

    @Override
    public Collection<PreferenceObject> definePreferenceObjectCollection() {
        Collection<PreferenceObject> preferenceObjectCollection = new ArrayList<>();

        String[] projectStringSettingNames = {"BurpTitle", "BurpIconCustomPath", "BurpResourceIconName"};
        String[] globalStringSettingNames = {"LastBurpIconCustomPath"};

        for (String settingName : projectStringSettingNames) {
            try {
                PreferenceObject preferenceObject = new PreferenceObject(settingName, String.class, "", Preferences.Visibility.PROJECT);
                preferenceObjectCollection.add(preferenceObject);
            } catch (Exception e) {
                //already registered setting
                sharedParameters.printDebugMessage(e.getMessage());
            }
        }

        for (String settingName : globalStringSettingNames) {
            try {
                PreferenceObject preferenceObject = new PreferenceObject(settingName, String.class, "", Preferences.Visibility.GLOBAL);
                preferenceObjectCollection.add(preferenceObject);
            } catch (Exception e) {
                //already registered setting
                sharedParameters.printDebugMessage(e.getMessage());
            }
        }

        PreferenceObject preferenceObject = new PreferenceObject("useLastScreenPositionAndSize", boolean.class, true, Preferences.Visibility.GLOBAL);
        preferenceObjectCollection.add(preferenceObject);

        preferenceObject = new PreferenceObject("detectOffScreenPosition", boolean.class, true, Preferences.Visibility.GLOBAL);
        preferenceObjectCollection.add(preferenceObject);

        preferenceObject = new PreferenceObject("lastApplicationPosition", Point.class, null, Preferences.Visibility.GLOBAL);
        preferenceObjectCollection.add(preferenceObject);

        preferenceObject = new PreferenceObject("lastApplicationSize", Dimension.class, null, Preferences.Visibility.GLOBAL);
        preferenceObjectCollection.add(preferenceObject);

        return preferenceObjectCollection;
    }

    @Override
    public void loadSettings() {
        sharedParameters.printDebugMessage("loadSettings");

        String newTitle = sharedParameters.preferences.safeGetStringSetting("BurpTitle");
        if (!newTitle.isBlank()) {
            BurpTitleAndIcon.setTitle(sharedParameters, newTitle);
        }

        String newIconPath = sharedParameters.preferences.safeGetStringSetting("BurpIconCustomPath");
        String newIconResourcePath = sharedParameters.preferences.safeGetStringSetting("BurpResourceIconName");
        if (!newIconPath.isBlank()) {
            sharedParameters.preferences.setSetting("LastBurpIconCustomPath", newIconPath);
            BurpTitleAndIcon.setIcon(sharedParameters, newIconPath, 48, false);
        } else if (!newIconResourcePath.isBlank()) {
            BurpTitleAndIcon.setIcon(sharedParameters, newIconResourcePath, 48, true);
        }

        boolean useLastScreenPositionAndSize = sharedParameters.preferences.safeGetBooleanSetting("useLastScreenPositionAndSize");
        //boolean detectOffScreenPosition = sharedParameters.preferences.safeGetBooleanSetting("detectOffScreenPosition");

        if(useLastScreenPositionAndSize){
            Point lastApplicationPosition = sharedParameters.preferences.safeGetSetting("lastApplicationPosition", null);
            Dimension lastApplicationSize = sharedParameters.preferences.safeGetSetting("lastApplicationSize", null);

            if(lastApplicationPosition != null){
                sharedParameters.get_mainFrameUsingMontoya().setLocation(lastApplicationPosition);
            }

            if(lastApplicationSize != null){
                sharedParameters.get_mainFrameUsingMontoya().setSize(lastApplicationSize);
            }
        }

        burpFrameListeners = new BurpFrameListeners(sharedParameters);
    }

    @Override
    public void unloadSettings() {
        sharedParameters.printDebugMessage("reset Burp title and icon");

        if(burpFrameListeners!=null){
            burpFrameListeners.removeBurpFrameListener(sharedParameters.get_mainFrameUsingMontoya());
        }

        // reset Burp title and icon
        BurpTitleAndIcon.resetTitle(sharedParameters);
        BurpTitleAndIcon.resetIcon(sharedParameters);

    }
}
