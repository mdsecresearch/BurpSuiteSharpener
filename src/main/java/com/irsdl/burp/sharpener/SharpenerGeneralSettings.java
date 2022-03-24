// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.objects.PreferenceObject;
import com.irsdl.burp.sharpener.objects.StandardSettings;
import com.irsdl.burp.sharpener.uiModifiers.burpFrame.BurpFrameSettings;
import com.irsdl.burp.sharpener.uiModifiers.subTabs.SubTabSettings;
import com.irsdl.burp.sharpener.uiModifiers.toolsTabs.MainToolsTabSettings;

import java.util.ArrayList;
import java.util.Collection;

public class SharpenerGeneralSettings extends StandardSettings {
    public SubTabSettings subTabSettings;
    public MainToolsTabSettings mainToolsTabSettings;
    public BurpFrameSettings burpFrameSettings;

    public SharpenerGeneralSettings(SharpenerSharedParameters sharedParameters) {
        super(sharedParameters);
    }

    @Override
    public void init() {

    }

    @Override
    public Collection<PreferenceObject> definePreferenceObjectCollection() {
        Collection<PreferenceObject> preferenceObjectCollection = new ArrayList<>();

        try {
            PreferenceObject preferenceObject = new PreferenceObject("checkForUpdate", boolean.class, false, Preferences.Visibility.GLOBAL);
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
        if (BurpUITools.reattachTools(sharedParameters.subTabSupportedTabs, sharedParameters.get_mainMenuBar())) {
            try {
                // to make sure UI has been updated
                sharedParameters.printlnOutput("Detached windows were found. We need to wait for a few seconds after reattaching the tabs.");
                Thread.sleep(3000);
            } catch (Exception e) {

            }
        }

        burpFrameSettings = new BurpFrameSettings(sharedParameters);
        mainToolsTabSettings = new MainToolsTabSettings(sharedParameters);
        subTabSettings = new SubTabSettings(sharedParameters);

        if ((boolean) sharedParameters.preferences.getSetting("checkForUpdate")) {
            SharpenerBurpExtender sharpenerBurpExtender = (SharpenerBurpExtender) sharedParameters.burpExtender;
            sharpenerBurpExtender.checkForUpdate();
        }
    }
}
