// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.mdsec.burp.sharpener.uiSelf.contextMenu;

import com.mdsec.burp.sharpener.CustomExtensionSharedParameters;
import com.mdsec.burp.sharpener.objects.PreferenceObject;
import com.mdsec.burp.sharpener.objects.StandardSettings;

import java.util.Collection;

public class ContextMenuSettings extends StandardSettings {
    protected ContextMenuSettings(CustomExtensionSharedParameters sharedParameters) {
        super(sharedParameters);
    }

    @Override
    public void init() {

    }

    @Override
    public Collection<PreferenceObject> definePreferenceObjectCollection() {
        return null;
    }

    @Override
    public void loadSettings() {

    }

    @Override
    public void unloadSettings() {

    }

}
