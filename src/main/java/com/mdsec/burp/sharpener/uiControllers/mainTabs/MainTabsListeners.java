// Burp Suite Extension Name: Sharpener
// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)
// Released initially as open source by MDSec - https://www.mdsec.co.uk
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener

package com.mdsec.burp.sharpener.uiControllers.mainTabs;

import com.mdsec.burp.sharpener.SharpenerSharedParameters;

import javax.swing.*;
import java.awt.event.ContainerEvent;
import java.awt.event.ContainerListener;

public class MainTabsListeners implements ContainerListener {
    private final SharpenerSharedParameters sharedParameters;
    private boolean isResetInProgress = false;

    public MainTabsListeners(SharpenerSharedParameters sharedParameters) {
        this.sharedParameters = sharedParameters;
        addTabListener(sharedParameters.get_rootTabbedPaneUsingMontoya());
    }

    public void addTabListener(JTabbedPane tabbedPane) {
        sharedParameters.printDebugMessage("addMainTabListener");
        tabbedPane.addContainerListener(this);
    }

    public void removeTabListener(JTabbedPane tabbedPane) {
        sharedParameters.printDebugMessage("removeMainTabListener");
        tabbedPane.removeContainerListener(this);
    }

    @Override
    public void componentAdded(ContainerEvent e) {
        if (e.getSource() instanceof JTabbedPane && !isResetInProgress) {
            setResetInProgress(true);
            new java.util.Timer().schedule(
                    new java.util.TimerTask() {
                        @Override
                        public void run() {
                            SwingUtilities.invokeLater(() -> {
                                MainTabsStyleHandler.resetMainTabsStylesFromSettings(sharedParameters);
                                setResetInProgress(false);
                            });
                        }
                    },
                    2000 // 2 seconds-delay to ensure all has been settled!
            );
        }

    }

    @Override
    public void componentRemoved(ContainerEvent e) {

    }

    public void setResetInProgress(boolean resetInProgress) {
        isResetInProgress = resetInProgress;
    }


}
