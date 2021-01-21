// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.uimodifiers.subtabs;

import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.generic.UIHelper;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ContainerEvent;
import java.awt.event.ContainerListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.function.Consumer;

public class SubTabWatcher implements ContainerListener {
    private final Consumer<MouseEvent> mouseEventConsumer;
    private final SharpenerSharedParameters sharedParameters;
    private boolean isUpdateInProgress = false;
    private PropertyChangeListener tabPropertyChangeListener;
    private PropertyChangeListener subTabPropertyChangeListener;
    private ArrayList<BurpUITools.MainTabs> accessibleTabs;

    public SubTabWatcher(SharpenerSharedParameters sharedParameters, Consumer<MouseEvent> mouseEventConsumer) {
        this.sharedParameters = sharedParameters;
        this.mouseEventConsumer = mouseEventConsumer;
    }

    public void addTabListener(JTabbedPane tabbedPane) {
        sharedParameters.printDebugMessages("addTabListener");
        tabbedPane.addContainerListener(this);
        accessibleTabs = new ArrayList<>();
        for (Component component : tabbedPane.getComponents()) {
            addListenerToSupportedTabbedPanels(tabbedPane, component);
        }
        checkNotLoadedSupportedTools();
    }

    public void removeTabListener(JTabbedPane tabbedPane) {
        sharedParameters.printDebugMessages("removeTabListener");
        tabbedPane.removeContainerListener(this);
        accessibleTabs = new ArrayList<>();
        for (Component component : tabbedPane.getComponents()) {
            removeListenerFromTabbedPanels(tabbedPane, component);
        }
        checkNotLoadedSupportedTools();
    }

    private void checkNotLoadedSupportedTools() {
        ArrayList<String> result = new ArrayList<>();

        if (accessibleTabs != null) {
            for (BurpUITools.MainTabs supportedTabs : sharedParameters.subTabWatcherSupportedTabs) {
                if (!accessibleTabs.contains(supportedTabs)) {
                    result.add(supportedTabs.toString());
                }
            }
        }

        if (!result.isEmpty()) {
            UIHelper.showWarningMessage("The following tool(s) could not be accessed: " + String.join(", ", result) + ".\r\nConsider attaching all the tools before reloading the " + sharedParameters.extensionName + " extension.", sharedParameters.get_mainFrame());
        }
    }

    @Override
    public void componentAdded(ContainerEvent e) {
        addListenerToSupportedTabbedPanels((JTabbedPane) e.getContainer(), e.getChild());
    }

    private void addListenerToSupportedTabbedPanels(JTabbedPane tabbedPane, Component tabComponent) {
        //Check tab titles and continue for accepted tab paths.
        int componentIndex = tabbedPane.indexOfComponent(tabComponent);
        if (componentIndex == -1) {
            return;
        }

        BurpUITools.MainTabs componentTitle = BurpUITools.getMainTabsObjFromString(tabbedPane.getTitleAt(componentIndex));

        if (!sharedParameters.subTabWatcherSupportedTabs.contains(componentTitle)) return;

        sharedParameters.printDebugMessages("Adding listener to " + componentTitle);

        accessibleTabs.add(componentTitle);

        tabComponent.addMouseListener(new SubTabClickHandler(this.mouseEventConsumer));

        // Loading all the tabs
        for (BurpUITools.MainTabs tool : sharedParameters.subTabWatcherSupportedTabs) {
            JTabbedPane subTabbedPane = sharedParameters.get_toolTabbedPane(tool);
            ArrayList<SubTabContainerHandler> subTabContainerHandlers = new ArrayList<>();
            if (subTabbedPane != null) {
                for (Component subTabComponent : subTabbedPane.getComponents()) {
                    int subTabIndex = subTabbedPane.indexOfComponent(subTabComponent);
                    if (subTabIndex == -1)
                        continue;
                    SubTabContainerHandler subTabContainerHandler = new SubTabContainerHandler(sharedParameters, subTabbedPane, subTabIndex);
                    subTabContainerHandlers.add(subTabContainerHandler);
                }
            }
            sharedParameters.allSubTabContainerHandlers.put(tool, subTabContainerHandlers);
        }

        tabPropertyChangeListener = new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if (!isUpdateInProgress && evt.getPropertyName().equalsIgnoreCase("indexForTabComponent")) {
                    // this is a dirty hack to keep the colours as they go black after drag and drop!
                    isUpdateInProgress = true;
                    new java.util.Timer().schedule(
                            new java.util.TimerTask() {
                                @Override
                                public void run() {
                                    sharedParameters.allSettings.subTabSettings.loadSettings();
                                    sharedParameters.allSettings.subTabSettings.saveSettings();
                                    isUpdateInProgress = false;
                                }
                            },
                            500
                    );
                }
            }
        };

        tabComponent.addPropertyChangeListener(tabPropertyChangeListener);
    }

    @Override
    public void componentRemoved(ContainerEvent e) {
        removeListenerFromTabbedPanels((JTabbedPane) e.getContainer(), e.getChild());
    }

    private void removeListenerFromTabbedPanels(JTabbedPane tabbedPane, Component tabComponent) {
        int componentIndex = tabbedPane.indexOfComponent(tabComponent);
        if (componentIndex == -1) {
            return;
        }

        BurpUITools.MainTabs componentTitle = BurpUITools.getMainTabsObjFromString(tabbedPane.getTitleAt(componentIndex));

        if (!sharedParameters.subTabWatcherSupportedTabs.contains(componentTitle)) return;

        accessibleTabs.add(componentTitle);

        for (MouseListener mouseListener : tabComponent.getMouseListeners()) {
            if (mouseListener instanceof SubTabClickHandler) {
                tabComponent.removeMouseListener(mouseListener);
            }
        }

        tabComponent.removePropertyChangeListener(tabPropertyChangeListener);
    }
}
