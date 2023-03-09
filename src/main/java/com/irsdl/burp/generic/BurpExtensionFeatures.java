// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.generic;

public class BurpExtensionFeatures {
    public boolean hasSuiteTab = false;
    public boolean hasContextMenu = false;
    public boolean isCommunityVersionCompatible = true;
    public double minSupportedMajorVersionInclusive = 0.0;
    public double maxSupportedMajorVersionInclusive = 0.0;
    public double minSupportedMinorVersionInclusive = 0.0;
    public double maxSupportedMinorVersionInclusive = 0.0;
    public boolean hasHttpHandler = false;
    public boolean hasProxyHandler = false;
    public BurpExtensionFeatures(){

    }
}
