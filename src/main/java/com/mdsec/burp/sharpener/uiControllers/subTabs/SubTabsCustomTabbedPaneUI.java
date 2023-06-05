// Burp Suite Extension Name: Sharpener
// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)
// Released initially as open source by MDSec - https://www.mdsec.co.uk
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener

package com.mdsec.burp.sharpener.uiControllers.subTabs;

import com.formdev.flatlaf.ui.FlatTabbedPaneUI;
import com.irsdl.burp.generic.BurpUITools;
import com.mdsec.burp.sharpener.SharpenerSharedParameters;

import java.awt.*;

public class SubTabsCustomTabbedPaneUI {
    public static FlatTabbedPaneUI getUI(SharpenerSharedParameters sharedParameters, BurpUITools.MainTabs currentToolTab) {
        boolean isMinimizeTabSize = sharedParameters.preferences.safeGetBooleanSetting("minimizeSize_" + currentToolTab);
        boolean isFixedTabPosition = sharedParameters.preferences.safeGetBooleanSetting("isTabFixedPosition_" + currentToolTab);
        boolean isFiltered = sharedParameters.isFiltered(currentToolTab);
        return getUI(sharedParameters, currentToolTab, isFiltered, isMinimizeTabSize, isFixedTabPosition);
    }

    public static FlatTabbedPaneUI getUI(SharpenerSharedParameters sharedParameters, BurpUITools.MainTabs currentToolTab,
                                         boolean isFiltered, boolean isMinimizeTabSize, boolean isFixedTabPosition) {
        return new FlatTabbedPaneUI() {
            @Override
            protected int calculateTabWidth(int tabPlacement, int tabIndex, FontMetrics metrics) {
                if (isFiltered) {
                    if (sharedParameters.allSubTabContainerHandlers.get(currentToolTab).stream()
                            .filter(s -> !s.getVisible() && s.getTabIndex() == tabIndex).toArray().length > 0) {
                        return 0;
                    }
                }
                return super.calculateTabWidth(tabPlacement, tabIndex, metrics);
            }

            @Override
            protected int calculateTabHeight(int tabPlacement, int tabIndex, int fontHeight) {
                if (isMinimizeTabSize || this.tabInsets == null) {
                    this.tabInsets = new Insets(1, 1, 1, 1);
                }
                return super.calculateTabHeight(tabPlacement, tabIndex, fontHeight);
            }

            @Override
            protected boolean shouldRotateTabRuns(int i) {
                return !isFixedTabPosition;
            }
        };
    }
}
