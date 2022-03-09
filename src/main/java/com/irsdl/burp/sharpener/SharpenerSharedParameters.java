// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import com.irsdl.burp.generic.BurpExtensionSharedParameters;
import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.objects.TabFeaturesObject;
import com.irsdl.burp.sharpener.objects.TabFeaturesObjectStyle;
import com.irsdl.burp.sharpener.uimodifiers.subtabs.SubTabContainerHandler;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

public class SharpenerSharedParameters extends BurpExtensionSharedParameters {
    public HashMap<BurpUITools.MainTabs, ArrayList<SubTabContainerHandler>> allSubTabContainerHandlers = new HashMap<>();
    public Set<BurpUITools.MainTabs> subTabWatcherSupportedTabs;
    public HashMap<BurpUITools.MainTabs, HashMap<String, TabFeaturesObject>> supportedTools_SubTabs = new HashMap<>();
    public SubTabContainerHandler defaultSubTabObject = null;
    public SharpenerGeneralSettings allSettings;
    public TabFeaturesObjectStyle copiedTabFeaturesObjectStyle;
    public String copiedTabTitle = "";
    public String searchedTabTitleForPasteStyle = "";
    public String matchReplaceTitle_RegEx = "";
    public String matchReplaceTitle_ReplaceWith = "";
    public String searchedTabTitleForJumpToTab = "";

    public SharpenerSharedParameters(String version, String extensionName, String extensionURL, String extensionIssueTracker, IBurpExtender burpExtenderObj, IBurpExtenderCallbacks callbacks) {
        super(version, extensionName, extensionURL, extensionIssueTracker, burpExtenderObj, callbacks);
        supportedTools_SubTabs.put(BurpUITools.MainTabs.Repeater, new HashMap<>());
        supportedTools_SubTabs.put(BurpUITools.MainTabs.Intruder, new HashMap<>());

        subTabWatcherSupportedTabs = supportedTools_SubTabs.keySet();
        this.printlnOutput("Sharpener has been loaded successfully");
    }

}
