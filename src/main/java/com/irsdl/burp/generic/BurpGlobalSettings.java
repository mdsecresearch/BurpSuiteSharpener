// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.generic;


public class BurpGlobalSettings {
    private final BurpExtensionSharedParameters sharedParams;

    public BurpGlobalSettings(BurpExtensionSharedParameters sharedParameters) {
        this.sharedParams = sharedParameters;
    }

    public Object getGlobalSetting(String name, String type, Object defaultValue) {

        Object value = null;
        try {
            String temp_value = sharedParams.callbacks.loadExtensionSetting(name);
            if (temp_value != null && !temp_value.equals("")) {
                switch (type.toLowerCase()) {
                    case "int":
                    case "integer":
                        value = Integer.valueOf(temp_value);
                        break;
                    case "bool":
                    case "boolean":
                        value = Boolean.valueOf(temp_value);
                        break;
                    default:
                        value = temp_value;
                        break;
                }
            }
        } catch (Exception e) {
            sharedParams.printlnError(e.getMessage());
        }

        if (value == null) {
            value = defaultValue;
        }
        return value;
    }

    public void setGlobalSetting(String name, Object value) {
        setGlobalSetting(name, value, null);
    }

    public void setGlobalSetting(String name, Object value, Object defaultValue) {
        try {
            if (value == null) {
                value = "";
            }
            sharedParams.callbacks.saveExtensionSetting(name, String.valueOf(value));
        } catch (Exception e1) {
            sharedParams.stderr.println(e1.getMessage());
            try {
                if (defaultValue == null) {
                    defaultValue = "";
                }
                sharedParams.callbacks.saveExtensionSetting(name, String.valueOf(defaultValue));

            } catch (Exception e2) {
                sharedParams.stderr.println(e2.getMessage());
            }
        }
    }

}
