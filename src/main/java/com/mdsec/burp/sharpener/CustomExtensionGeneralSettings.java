// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.mdsec.burp.sharpener;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.irsdl.burp.generic.BurpUITools;
import com.mdsec.burp.sharpener.capabilities.pwnFox.PwnFoxSettings;
import com.mdsec.burp.sharpener.uiControllers.burpFrame.BurpFrameSettings;
import com.mdsec.burp.sharpener.uiControllers.mainTabs.MainTabsSettings;
import com.mdsec.burp.sharpener.uiControllers.subTabs.SubTabsSettings;
import com.mdsec.burp.sharpener.uiSelf.topMenu.TopMenuSettings;
import com.mdsec.burp.sharpener.objects.PreferenceObject;
import com.mdsec.burp.sharpener.objects.StandardSettings;

import java.util.ArrayList;
import java.util.Collection;

public class CustomExtensionGeneralSettings extends StandardSettings {
    public SubTabsSettings subTabsSettings;
    public MainTabsSettings mainTabsSettings;
    public BurpFrameSettings burpFrameSettings;
    public TopMenuSettings topMenuSettings;
    public PwnFoxSettings pwnFoxSettings;

    public CustomExtensionGeneralSettings(CustomExtensionSharedParameters sharedParameters) {
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
            preferenceObject = new PreferenceObject("checkForUpdate", boolean.class, false, Preferences.Visibility.GLOBAL);
            preferenceObjectCollection.add(preferenceObject);
        } catch (Exception e) {
            //already registered setting
            sharedParameters.printDebugMessage(e.getMessage());
        }

        return preferenceObjectCollection;


    }

    @Override
    public void loadSettings() {
        // reattaching related tools before working on them!
        if (BurpUITools.reattachTools(sharedParameters.subTabSupportedTabs, sharedParameters.get_mainMenuBarUsingMontoya())) {
            try {
                // to make sure UI has been updated
                sharedParameters.printlnOutput("Detached windows were found. We need to wait for a few seconds after reattaching the tabs.");
                Thread.sleep(3000);
            } catch (Exception e) {
                sharedParameters.printDebugMessage("Error in SharpenerGeneralSettings.loadSettings(): " + e.getMessage());
            }
        }

        topMenuSettings = new TopMenuSettings(sharedParameters);
        burpFrameSettings = new BurpFrameSettings(sharedParameters);
        mainTabsSettings = new MainTabsSettings(sharedParameters);
        subTabsSettings = new SubTabsSettings(sharedParameters);
        pwnFoxSettings = new PwnFoxSettings(sharedParameters);

        if (sharedParameters.preferences.safeGetSetting("checkForUpdate", false)) {
            CustomExtensionMainClass sharpenerBurpExtension = (CustomExtensionMainClass) sharedParameters.burpExtender;
            sharpenerBurpExtension.checkForUpdate();
        }
    }

    @Override
    public void unloadSettings() {
        if(burpFrameSettings!=null){
            burpFrameSettings.unloadSettings();
        }

        if(mainTabsSettings != null){
            mainTabsSettings.unloadSettings();
        }

        if(subTabsSettings != null){
            subTabsSettings.unloadSettings();
        }

        if(pwnFoxSettings != null){
            pwnFoxSettings.unloadSettings();
        }

        if(topMenuSettings != null){
            topMenuSettings.unloadSettings();
        }
    }
}
