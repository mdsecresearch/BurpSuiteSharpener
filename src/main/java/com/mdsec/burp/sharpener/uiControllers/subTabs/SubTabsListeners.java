// Burp Suite Extension Name: Sharpener
// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)
// Released initially as open source by MDSec - https://www.mdsec.co.uk
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener

package com.mdsec.burp.sharpener.uiControllers.subTabs;

import com.irsdl.burp.generic.BurpUITools;
import com.mdsec.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.generic.MouseAdapterExtensionHandler;
import com.irsdl.generic.UIHelper;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Timer;
import java.util.TimerTask;
import java.util.function.Consumer;

public class SubTabsListeners implements ContainerListener {
    private final Consumer<MouseEvent> mouseEventConsumer;
    private final SharpenerSharedParameters sharedParameters;
    private boolean _isUpdateInProgress = false;
    private ArrayList<BurpUITools.MainTabs> accessibleTabs;
    private final boolean _isShortcutEnabled = true;
    public HashMap<String, String> subTabsShortcutMappings = new HashMap<>() {{
        put("control ENTER", "ShowMenu");
        put("control shift ENTER", "ShowMenu");
        put("DOWN", "ShowMenu");
        put("control shift F", "FindTabs");
        put("F3", "NextFind");
        put("control F3", "NextFind");
        put("shift F3", "PreviousFind");
        put("control shift F3", "PreviousFind");
        put("HOME", "FirstTab");
        put("END", "LastTab");
        put("control shift HOME", "FirstTab");
        put("control shift END", "LastTab");
        put("LEFT", "PreviousTab");
        put("RIGHT", "NextTab");
        put("control shift LEFT", "PreviousTab");
        put("control shift RIGHT", "NextTab");
        put("alt LEFT", "PreviouslySelectedTab");
        put("alt RIGHT", "NextlySelectedTab");
        put("control alt LEFT", "PreviouslySelectedTab");
        put("control alt RIGHT", "NextlySelectedTab");
        put("control C", "CopyTitle");
        put("control shift C", "CopyTitle");
        put("control V", "PasteTitle");
        put("control shift V", "PasteTitle");
        put("F2", "RenameTitle");
        put("control F2", "RenameTitle");
    }};

    public SubTabsListeners(SharpenerSharedParameters sharedParameters, Consumer<MouseEvent> mouseEventConsumer) {
        this.sharedParameters = sharedParameters;
        this.mouseEventConsumer = mouseEventConsumer;
        removeTabListener(sharedParameters.get_rootTabbedPaneUsingMontoya());
        addTabListener(sharedParameters.get_rootTabbedPaneUsingMontoya());
    }

    public void addTabListener(JTabbedPane tabbedPane) {
        sharedParameters.printDebugMessage("addSubTabListener");
        tabbedPane.addContainerListener(this);
        accessibleTabs = new ArrayList<>();

        for (Component component : tabbedPane.getComponents()) {
            addListenerToSupportedTabbedPanels(tabbedPane, component);
        }

        checkNotLoadedSupportedTools();
    }

    public void removeTabListener(JTabbedPane tabbedPane) {
        sharedParameters.printDebugMessage("removeSubTabListener");
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
            for (BurpUITools.MainTabs supportedTabs : sharedParameters.subTabSupportedTabs) {
                if (!accessibleTabs.contains(supportedTabs)) {
                    result.add(supportedTabs.toString());
                }
            }
        }

        if (!result.isEmpty()) {
            String message = "The following tool(s) could not be accessed: " + String.join(", ", result) + ".\r\nConsider attaching all the tools before reloading the " + sharedParameters.extensionName + " extension.";
            if(!sharedParameters.get_isUILoaded() || sharedParameters.allSettings.subTabsSettings.isFirstLoad){
                UIHelper.showWarningMessage(message, sharedParameters.get_mainFrameUsingMontoya());
            }else{
                sharedParameters.printOutput(message);
            }
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
            componentIndex = tabbedPane.indexOfTabComponent(tabComponent);
        }

        if (componentIndex == -1) {
            return;
        }

        final BurpUITools.MainTabs toolName = BurpUITools.getMainTabsObjFromString(tabbedPane.getTitleAt(componentIndex));

        if (!sharedParameters.subTabSupportedTabs.contains(toolName)) return;

        sharedParameters.printDebugMessage("Adding listener to " + toolName);

        accessibleTabs.add(toolName);


        // Burp has changed something in the UI, so we need this if condition to support older versions
        Component targetComponent;

        if (tabComponent.getMouseListeners().length > 0) {
            targetComponent = tabComponent;
        } else {
            targetComponent = tabComponent.getComponentAt(0, 0);
        }

        // this is a dirty hack to keep the colours as they go black after drag and drop!
        // this also makes sure we always have the latest version of the tabs saved in the variables after add/remove
        // this is enough for repeater but Intruder changes the colour, so it should be higher
        PropertyChangeListener tabPropertyChangeListener = evt -> {
            if (!get_isUpdateInProgress() && evt.getPropertyName().equalsIgnoreCase("indexForTabComponent")) {
                // this is a dirty hack to keep the colours as they change after drag and drop!
                // this also makes sure we always have the latest version of the tabs saved in the variables after add/remove
                // this is in charge of adding the right click menu to the new tabs by doing this
                set_isUpdateInProgress(true);

                int delay = 3000; // this is enough for repeater but Intruder changes the colour, so it should be higher
                if (toolName.equals(BurpUITools.MainTabs.Intruder)) {
                    delay = 10000;
                }

                new Timer().schedule(
                        new TimerTask() {
                            @Override
                            public void run() {
                                SwingUtilities.invokeLater(() -> {
                                    set_isUpdateInProgress(true);
                                    sharedParameters.allSettings.subTabsSettings.loadSettings(toolName);
                                    sharedParameters.allSettings.subTabsSettings.saveSettings(toolName);
                                    set_isUpdateInProgress(false);
                                });
                            }
                        },
                        delay
                );
            }
        };

        // Loading all the tabs

        var currentToolTabbedPane = sharedParameters.get_toolTabbedPane(toolName);

        targetComponent.addPropertyChangeListener("indexForTabComponent", tabPropertyChangeListener);

        if (currentToolTabbedPane != null) {
            addSubTabsListener(currentToolTabbedPane, toolName);
        } else {
            // when Burp Suite is loaded for the first time, Repeater and Intruder tabs are empty in the latest versions rather than having one tab
            // This is to address the issue of component change when the first tab is being created
            targetComponent.addComponentListener(new ComponentListener() {
                @Override
                public void componentResized(ComponentEvent e) {
                }

                @Override
                public void componentMoved(ComponentEvent e) {
                }

                @Override
                public void componentShown(ComponentEvent e) {
                }

                @Override
                public void componentHidden(ComponentEvent e) {
                    new java.util.Timer().schedule(
                            new java.util.TimerTask() {
                                @Override
                                public void run() {
                                    SwingUtilities.invokeLater(() -> {
                                        // This will be triggered when Burp creates items in Repeater or Intruder
                                        BurpUITools.MainTabs currentToolName = BurpUITools.getMainTabsObjFromString(sharedParameters.get_rootTabbedPaneUsingMontoya().getTitleAt(sharedParameters.get_rootTabbedPaneUsingMontoya().indexOfComponent(((Component) e.getSource()).getParent())));
                                        var currentToolTabbedPane = sharedParameters.get_toolTabbedPane(currentToolName);
                                        if (currentToolTabbedPane != null) {
                                            if (currentToolTabbedPane.getPropertyChangeListeners("tabPropertyChangeListener").length == 0)
                                                currentToolTabbedPane.addPropertyChangeListener("indexForTabComponent", tabPropertyChangeListener);

                                            addSubTabsListener(currentToolTabbedPane, currentToolName);

                                            // as there is no other getComponentListeners by default, we can remove them all
                                            for (ComponentListener cl : currentToolTabbedPane.getComponentListeners()) {
                                                currentToolTabbedPane.removeComponentListener(cl);
                                            }

                                            sharedParameters.allSettings.subTabsSettings.loadSettings(currentToolName);
                                            sharedParameters.allSettings.subTabsSettings.saveSettings(currentToolName);
                                            set_isUpdateInProgress(false);
                                        }
                                    });
                                }
                            },
                            5000 // 5 seconds delay just in case Burp is very slow on the device
                    );
                }
            });
        }

    }

    @Override
    public void componentRemoved(ContainerEvent e) {
        removeListenerFromTabbedPanels((JTabbedPane) e.getContainer(), e.getChild());
    }

    private void addSubTabsListener(JTabbedPane subTabbedPane, BurpUITools.MainTabs toolName) {
        if (sharedParameters.allSubTabContainerHandlers.get(toolName) == null ||
                (sharedParameters.allSubTabContainerHandlers.get(toolName).size() != subTabbedPane.getTabCount() - 1 && !sharedParameters.isTabGroupSupportedByDefault)) {
            ArrayList<SubTabsContainerHandler> subTabsContainerHandlers = new ArrayList<>();
            for (int subTabIndex = 0; subTabIndex < subTabbedPane.getTabCount(); subTabIndex++) {
                SubTabsContainerHandler subTabsContainerHandler = new SubTabsContainerHandler(sharedParameters, subTabbedPane, subTabIndex, false);
                subTabsContainerHandlers.add(subTabsContainerHandler);
            }

            // this for dotdotdot tab!
            if (sharedParameters.burpMajorVersion < 2022
                    || (sharedParameters.burpMajorVersion == 2022 && sharedParameters.burpMinorVersion < 6)) { // before version 2022.6
                SubTabsContainerHandler tempDotDotDotSubTabsContainerHandler = new SubTabsContainerHandler(sharedParameters, subTabbedPane, subTabbedPane.getTabCount() - 1, true);
                if (!subTabsContainerHandlers.contains(tempDotDotDotSubTabsContainerHandler)) {
                    // we have a new tab
                    tempDotDotDotSubTabsContainerHandler.addSubTabWatcher();
                    subTabsContainerHandlers.add(tempDotDotDotSubTabsContainerHandler);
                }
            }
            sharedParameters.allSubTabContainerHandlers.put(toolName, subTabsContainerHandlers);
        }

        subTabbedPane.addMouseListener(new MouseAdapterExtensionHandler(mouseEventConsumer, MouseEvent.MOUSE_RELEASED));

        //Defining shortcuts for search in tab titles: ctrl+shift+f , F3, shift+F3
        if (_isShortcutEnabled) {
            clearInputMap(subTabbedPane);
            subTabsShortcutMappings.forEach((k, v) -> subTabbedPane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
                    KeyStroke.getKeyStroke(k), v));

            subTabbedPane.getActionMap().put("ShowMenu", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabsActions.showPopupMenu(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("FindTabs", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabsActions.defineRegExPopupForSearchAndJump(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("NextFind", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabsActions.searchInTabTitlesAndJump(sharedParameters, e, true);
                }
            });
            subTabbedPane.getActionMap().put("PreviousFind", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabsActions.searchInTabTitlesAndJump(sharedParameters, e, false);
                }
            });
            subTabbedPane.getActionMap().put("FirstTab", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabsActions.jumpToFirstTab(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("LastTab", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabsActions.jumpToLastTab(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("PreviousTab", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabsActions.jumpToPreviousTab(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("NextTab", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabsActions.jumpToNextTab(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("PreviouslySelectedTab", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabsActions.jumpToPreviouslySelectedTab(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("NextlySelectedTab", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabsActions.jumpToNextlySelectedTab(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("CopyTitle", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabsActions.copyTitle(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("PasteTitle", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabsActions.pasteTitle(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("RenameTitle", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabsActions.renameTitle(sharedParameters, e);
                }
            });
        }
        //tabComponent.removeMouseListener(tabComponent.getMouseListeners()[1]); --> this will remove the current right click menu!

        sharedParameters.printDebugMessage("Menu has now been loaded for " + toolName.toString());
    }

    private void removeListenerFromTabbedPanels(JTabbedPane tabbedPane, Component tabComponent) {
        int componentIndex = tabbedPane.indexOfComponent(tabComponent);
        if (componentIndex == -1) {
            return;
        }

        BurpUITools.MainTabs toolName = BurpUITools.getMainTabsObjFromString(tabbedPane.getTitleAt(componentIndex));

        if (!sharedParameters.subTabSupportedTabs.contains(toolName)) return;

        accessibleTabs.add(toolName);

        // Burp has changed something in the UI, so we need this if condition to support older versions
        JComponent targetComponent;

        if (tabComponent.getMouseListeners().length > 0) {
            targetComponent = (JComponent) tabComponent;
        } else {
            targetComponent = (JComponent) tabComponent.getComponentAt(0, 0);
        }

        // as there is no other PropertyChangeListener with propertyName of "indexForTabComponent" by default, we can remove them all
        PropertyChangeListener[] pclArray = targetComponent.getPropertyChangeListeners("indexForTabComponent");
        for (PropertyChangeListener pcl : pclArray) {
            targetComponent.removePropertyChangeListener("indexForTabComponent", pcl);
        }

        // as there is no other getComponentListeners by default, we can remove them all
        for (ComponentListener cl : targetComponent.getComponentListeners()) {
            targetComponent.removeComponentListener(cl);
        }

        for (MouseListener mouseListener : targetComponent.getMouseListeners()) {
            if (mouseListener instanceof MouseAdapterExtensionHandler) {
                targetComponent.removeMouseListener(mouseListener);
            }
        }

        // as there is no other getKeyListeners by default, we can remove them all
        for (KeyListener keyListener : targetComponent.getKeyListeners()) {
            targetComponent.removeKeyListener(keyListener);
        }

        // There is no bindings on these items, so it can be cleared
        if (_isShortcutEnabled) {
            clearInputMap(targetComponent);
        }
    }

    private void clearInputMap(JComponent jc) {
        subTabsShortcutMappings.forEach((k, v) -> jc.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(
                KeyStroke.getKeyStroke(k), "none"));
    }

    private void set_isUpdateInProgress(boolean _isUpdateInProgress) {
        this._isUpdateInProgress = _isUpdateInProgress;
    }

    private boolean get_isUpdateInProgress() {
        return this._isUpdateInProgress;
    }
}
