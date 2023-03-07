// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.mdsec.burp.sharpener.objects;

import com.coreyd97.BurpExtenderUtilities.Preferences;

import java.lang.reflect.Type;

public class PreferenceObject {
    public String settingName;
    public Type type;
    public Object defaultValue;
    public Preferences.Visibility visibility;

    public PreferenceObject(String settingName, Type type, Object defaultValue, Preferences.Visibility visibility) {
        this.settingName = settingName;
        this.type = type;
        this.defaultValue = defaultValue;
        this.visibility = visibility;
    }
}
