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
import com.irsdl.burp.sharpener.actitivities.ui.subTabs.SubTabsContainerHandler;
import com.irsdl.burp.sharpener.actitivities.ui.topMenu.TopMenu;
import com.irsdl.burp.sharpener.objects.TabFeaturesObject;
import com.irsdl.burp.sharpener.objects.TabFeaturesObjectStyle;
import com.irsdl.generic.uiObjFinder.UISpecObject;

import javax.swing.*;
import javax.swing.plaf.TabbedPaneUI;
import java.awt.*;
import java.util.*;

public class SharpenerSharedParameters extends BurpExtensionSharedParameters {
    public TopMenu topMenuBar;
    public HashMap<BurpUITools.MainTabs, ArrayList<SubTabsContainerHandler>> allSubTabContainerHandlers = new HashMap<>();
    public Set<BurpUITools.MainTabs> subTabSupportedTabs = new HashSet<>();
    public HashMap<BurpUITools.MainTabs, HashMap<String, TabFeaturesObject>> supportedTools_SubTabs = new HashMap<>();
    public TabFeaturesObjectStyle defaultTabFeaturesObjectStyle = null;
    public SharpenerGeneralSettings allSettings;
    public TabFeaturesObjectStyle copiedTabFeaturesObjectStyle;
    public String lastClipboardText = "";
    public String searchedTabTitleForPasteStyle = "";
    public String matchReplaceTitle_RegEx = "";
    public String matchReplaceTitle_ReplaceWith = "";
    public String searchedTabTitleForJumpToTab = "";
    public String titleFilterRegEx = "";
    public boolean isTitleFilterNegative = false;
    public boolean isTabGroupSupportedByDefault = false;
    public boolean isSubTabScrollSupportedByDefault = false;
    public HashMap<BurpUITools.MainTabs, Integer> filterOperationMode = new HashMap<>();
    public HashMap<BurpUITools.MainTabs, LinkedList<Integer>> subTabPreviouslySelectedIndexHistory = new HashMap<>();
    public HashMap<BurpUITools.MainTabs, LinkedList<Integer>> subTabNextlySelectedIndexHistory = new HashMap<>();
    public HashMap<BurpUITools.MainTabs, TabbedPaneUI> originalSubTabbedPaneUI = new HashMap<>();
    private HashMap<BurpUITools.MainTabs, JTabbedPane> cachedJTabbedPaneTools = new HashMap<>(); // This will keep pointer to the current repeater or intruder even when they are detached

    public SharpenerSharedParameters(String version, String extensionName, String extensionURL, String extensionIssueTracker, IBurpExtender burpExtenderObj, IBurpExtenderCallbacks callbacks) {
        super(version, extensionName, extensionURL, extensionIssueTracker, burpExtenderObj, callbacks);

        if ((burpMajorVersion >= 2022 && burpMinorVersion >= 6) || burpMajorVersion >= 2023) {
            this.isTabGroupSupportedByDefault = true;
            this.isSubTabScrollSupportedByDefault = true;
        }

        subTabSupportedTabs.add(BurpUITools.MainTabs.Repeater);
        subTabSupportedTabs.add(BurpUITools.MainTabs.Intruder);

        for (BurpUITools.MainTabs supportedTabs : subTabSupportedTabs) {
            supportedTools_SubTabs.put(supportedTabs, new HashMap<>());
            filterOperationMode.put(supportedTabs, 0);
            subTabPreviouslySelectedIndexHistory.put(supportedTabs, new LinkedList<>());
            subTabNextlySelectedIndexHistory.put(supportedTabs, new LinkedList<>());
        }

        this.printlnOutput(extensionName + " is being loaded...");
    }

    public boolean isFiltered(BurpUITools.MainTabs toolTabName) {
        if (getHiddenSubTabsCount(toolTabName) > 0) {
            return true;
        } else {
            return false;
        }
    }

    public int getHiddenSubTabsCount(BurpUITools.MainTabs toolTabName) {
        if (allSubTabContainerHandlers.get(toolTabName) == null)
            return -1;
        else
            return allSubTabContainerHandlers.get(toolTabName).stream().filter(s -> s.isValid() && !s.getVisible()).toArray().length;
    }

    public JTabbedPane get_toolTabbedPane(BurpUITools.MainTabs toolTabName) {
        return get_toolTabbedPane(toolTabName, true);
    }

    public JTabbedPane get_toolTabbedPane(BurpUITools.MainTabs toolTabName, boolean useCache) {
        JTabbedPane subTabbedPane = null;
        JTabbedPane _rootTabbedPane = get_rootTabbedPane();


        if (useCache && cachedJTabbedPaneTools.get(toolTabName) != null) {
            subTabbedPane = cachedJTabbedPaneTools.get(toolTabName);
            try {
                subTabbedPane.getSelectedComponent();
            } catch (Exception e) {
                // could not access the object
                subTabbedPane = null;
            }
        }

        if (_rootTabbedPane != null && subTabbedPane == null) {
            for (Component tabComponent : _rootTabbedPane.getComponents()) {

                //Check tab titles and continue for accepted tab paths.
                int componentIndex = _rootTabbedPane.indexOfComponent(tabComponent);
                if (componentIndex == -1) {
                    continue;
                }
                String componentTitle = _rootTabbedPane.getTitleAt(componentIndex);

                if (toolTabName.toString().equalsIgnoreCase(componentTitle)) {
                    // we have our tool tab, now we need to find its right component
                    try {
                        subTabbedPane = (JTabbedPane) tabComponent;
                    } catch (Exception e1) {
                        try {
                            subTabbedPane = (JTabbedPane) tabComponent.getComponentAt(0, 0);
                        } catch (Exception e2) {
                            printDebugMessage("The " + componentTitle + " tool seems to be empty or different. Cannot find the tabs.");
                        }
                    }
                    break;
                }
            }

            if (subTabbedPane == null) {
                // it could not find the tool, this can happen when a tool has been detached so we need to look for it!
                for (Window window : Window.getWindows()) {
                    if (window.isShowing()) {
                        if (window instanceof JFrame) {
                            String title = ((JFrame) window).getTitle();
                            // "Repeater" becomes "Burp Repeater" when it is detached
                            if (title.equalsIgnoreCase("Burp " + toolTabName.toString())) {
                                com.irsdl.generic.uiObjFinder.UISpecObject uiSpecObject = new UISpecObject(JTabbedPane.class);
                                uiSpecObject.set_isJComponent(true);
                                uiSpecObject.set_isShowing(true);
                                uiSpecObject.set_minJComponentCount(1);
                                Component tempComponent = com.irsdl.generic.uiObjFinder.UIWalker.FindUIObjectInSubComponents(window.getComponents()[0], 6, uiSpecObject);
                                if (tempComponent != null) {
                                    subTabbedPane = (JTabbedPane) tempComponent;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        if (subTabbedPane != null) {
            if (cachedJTabbedPaneTools.get(toolTabName) != null) {
                cachedJTabbedPaneTools.replace(toolTabName, subTabbedPane);
            } else {
                cachedJTabbedPaneTools.put(toolTabName, subTabbedPane);
            }
        }

        return subTabbedPane;
    }

}
