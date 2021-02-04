// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener;

import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.objects.PreferenceObject;
import com.irsdl.burp.sharpener.objects.StandardSettings;
import com.irsdl.burp.sharpener.uimodifiers.burpframe.BurpFrameSettings;
import com.irsdl.burp.sharpener.uimodifiers.subtabs.SubTabSettings;
import com.irsdl.burp.sharpener.uimodifiers.toolstabs.ToolsTabSettings;

import java.util.Collection;

public class SharpenerGeneralSettings extends StandardSettings {
    public SubTabSettings subTabSettings;
    public ToolsTabSettings toolsTabSettings;
    public BurpFrameSettings burpFrameSettings;

    public SharpenerGeneralSettings(SharpenerSharedParameters sharedParameters) {
        super(sharedParameters);
    }

    @Override
    public Collection<PreferenceObject> definePreferenceObjectCollection() {
        return null;
    }

    @Override
    public synchronized void loadSettings() {
        // reattaching related tools before working on them!
        if (BurpUITools.reattachTools(sharedParameters.subTabWatcherSupportedTabs, sharedParameters.get_mainMenuBar())) {
            try {
                // to make sure UI has been updated
                sharedParameters.printlnOutput("Detached windows were found. We need to wait for a few seconds after reattaching the tabs.");
                Thread.sleep(3000);
            } catch (Exception e) {

            }
        }

        burpFrameSettings = new BurpFrameSettings(sharedParameters);
        toolsTabSettings = new ToolsTabSettings(sharedParameters);
        subTabSettings = new SubTabSettings(sharedParameters);
    }
}
