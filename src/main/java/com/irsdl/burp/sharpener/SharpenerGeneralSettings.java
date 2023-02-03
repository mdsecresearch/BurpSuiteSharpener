// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.capabilities.pwnFox.PwnFoxSettings;
import com.irsdl.burp.sharpener.uiControllers.burpFrame.BurpFrameSettings;
import com.irsdl.burp.sharpener.uiControllers.mainTabs.MainTabsSettings;
import com.irsdl.burp.sharpener.uiControllers.subTabs.SubTabsSettings;
import com.irsdl.burp.sharpener.uiSelf.topMenu.TopMenuSettings;
import com.irsdl.burp.sharpener.objects.PreferenceObject;
import com.irsdl.burp.sharpener.objects.StandardSettings;

import java.util.ArrayList;
import java.util.Collection;

public class SharpenerGeneralSettings extends StandardSettings {
    public SubTabsSettings subTabsSettings;
    public MainTabsSettings mainTabsSettings;
    public BurpFrameSettings burpFrameSettings;
    public TopMenuSettings topMenuSettings;
    public PwnFoxSettings pwnFoxSettings;

    public SharpenerGeneralSettings(SharpenerSharedParameters sharedParameters) {
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
    public synchronized void loadSettings() {
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
            SharpenerBurpExtender sharpenerBurpExtender = (SharpenerBurpExtender) sharedParameters.burpExtender;
            sharpenerBurpExtender.checkForUpdate();
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
