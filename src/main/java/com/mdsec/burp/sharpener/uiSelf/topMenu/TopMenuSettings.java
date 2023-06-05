// Burp Suite Extension Name: Sharpener
// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)
// Released initially as open source by MDSec - https://www.mdsec.co.uk
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener

package com.mdsec.burp.sharpener.uiSelf.topMenu;

import com.mdsec.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.objects.PreferenceObject;
import com.irsdl.objects.StandardSettings;

import java.util.Collection;
import java.util.Collections;

public class TopMenuSettings extends StandardSettings {

    public TopMenuSettings(SharpenerSharedParameters sharedParameters) {
        super(sharedParameters);
        sharedParameters.printDebugMessage("TopMenuSettings");
    }
    @Override
    public void init() {

    }

    @Override
    public Collection<PreferenceObject> definePreferenceObjectCollection() {
        return Collections.emptyList();
    }

    @Override
    public void loadSettings() {
        // Adding the top menu
        try {
            if (sharedParameters.topMenuBar != null) {
                sharedParameters.printDebugMessage("Removing the top menu before adding it again");
                sharedParameters.topMenuBar.removeTopMenuBar();
            }
            sharedParameters.printDebugMessage("Adding the top menu");
            sharedParameters.topMenuBar = new TopMenu(sharedParameters);
            sharedParameters.topMenuBar.addTopMenuBar();
        } catch (Exception e) {
            sharedParameters.stderr.println("Error in creating the top menu: " + e.getMessage());
        }
    }

    @Override
    public void unloadSettings() {
        sharedParameters.printDebugMessage("removing toolbar menu");
        // removing toolbar menu
        if (sharedParameters.topMenuBar != null)
            sharedParameters.topMenuBar.removeTopMenuBar();
    }
}
