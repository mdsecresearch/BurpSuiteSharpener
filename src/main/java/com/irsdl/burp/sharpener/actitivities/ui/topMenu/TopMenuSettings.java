// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.actitivities.ui.topMenu;

import com.irsdl.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.burp.sharpener.objects.PreferenceObject;
import com.irsdl.burp.sharpener.objects.StandardSettings;

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
