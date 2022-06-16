// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.uiModifiers.toolsTabs;

import com.irsdl.burp.sharpener.SharpenerSharedParameters;

import javax.swing.*;
import java.awt.event.ContainerEvent;
import java.awt.event.ContainerListener;
import java.awt.event.MouseEvent;
import java.util.function.Consumer;

public class MainToolsTabWatcher implements ContainerListener {
    private final Consumer<MouseEvent> mouseEventConsumer;
    private final SharpenerSharedParameters sharedParameters;
    private boolean isResetInProgress = false;

    public MainToolsTabWatcher(SharpenerSharedParameters sharedParameters, Consumer<MouseEvent> mouseEventConsumer) {
        this.sharedParameters = sharedParameters;
        this.mouseEventConsumer = mouseEventConsumer;
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
                            SwingUtilities.invokeLater(new Runnable() {
                                @Override
                                public void run() {
                                    MainToolsTabStyleHandler.resetToolTabStylesFromSettings(sharedParameters);
                                    setResetInProgress(false);
                                }
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

    public synchronized void setResetInProgress(boolean resetInProgress) {
        isResetInProgress = resetInProgress;
    }


}
