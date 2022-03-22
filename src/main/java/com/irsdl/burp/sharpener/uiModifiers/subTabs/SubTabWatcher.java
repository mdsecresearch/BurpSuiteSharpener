// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.uiModifiers.subTabs;

import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.generic.MouseAdapterExtensionHandler;
import com.irsdl.generic.UIHelper;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Timer;
import java.util.TimerTask;
import java.util.function.Consumer;

public class SubTabWatcher implements ContainerListener {
    private final Consumer<MouseEvent> mouseEventConsumer;
    private final SharpenerSharedParameters sharedParameters;
    private boolean _isUpdateInProgress = false;
    private ArrayList<BurpUITools.MainTabs> accessibleTabs;
    private boolean _isShortcutEnabled = true;
    public HashMap<String,String> subTabsShortcutMappings = new HashMap<String, String>() {{
        put("control ENTER","ShowMenu");
        put("control shift ENTER","ShowMenu");
        put("DOWN","ShowMenu");
        put("control shift F","FindTabs");
        put("F3","NextFind");
        put("control F3","NextFind");
        put("shift F3","PreviousFind");
        put("control shift F3","PreviousFind");
        put("HOME","FirstTab");
        put("END","LastTab");
        put("control shift HOME","FirstTab");
        put("control shift END","LastTab");
        put("LEFT","PreviousTab");
        put("RIGHT","NextTab");
        put("control shift LEFT","PreviousTab");
        put("control shift RIGHT","NextTab");
        put("alt LEFT","PreviouslySelectedTab");
        put("alt RIGHT","NextlySelectedTab");
        put("control alt LEFT","PreviouslySelectedTab");
        put("control alt RIGHT","NextlySelectedTab");
    }};

    public SubTabWatcher(SharpenerSharedParameters sharedParameters, Consumer<MouseEvent> mouseEventConsumer) {
        this.sharedParameters = sharedParameters;
        this.mouseEventConsumer = mouseEventConsumer;
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

        final BurpUITools.MainTabs toolName = BurpUITools.getMainTabsObjFromString(tabbedPane.getTitleAt(componentIndex));

        if (!sharedParameters.subTabSupportedTabs.contains(toolName)) return;

        sharedParameters.printDebugMessage("Adding listener to " + toolName);

        accessibleTabs.add(toolName);


        // Burp has changed something in the UI so we need this if condition to support older versions
        Component targetComponent;

        if(tabComponent.getMouseListeners().length > 0){
            targetComponent = tabComponent;
        }else{
            //tabComponent.getComponentAt(0,0).addMouseListener(new SubTabClickHandler(this.mouseEventConsumer));
            targetComponent = tabComponent.getComponentAt(0,0);
        }

        // this is a dirty hack to keep the colours as they go black after drag and drop!
        // this also makes sure we always have the latest version of the tabs saved in the variables after add/remove
        // this is enough for repeater but Intruder changes the colour, so it should be higher
        PropertyChangeListener tabPropertyChangeListener = new PropertyChangeListener() {
            @Override
            public void propertyChange(PropertyChangeEvent evt) {
                if (!get_isUpdateInProgress() && evt.getPropertyName().equalsIgnoreCase("indexForTabComponent")) {
                    // this is a dirty hack to keep the colours as they go black after drag and drop!
                    // this also makes sure we always have the latest version of the tabs saved in the variables after add/remove
                    // this is in charge of adding the right click menu to the new tabs by doing this
                    set_isUpdateInProgress(true);
                    //sharedParameters.allSettings.subTabSettings.loadSettings(toolName);

                    int delay = 3000; // this is enough for repeater but Intruder changes the colour, so it should be higher
                    if (toolName.equals(BurpUITools.MainTabs.Intruder)) {
                        delay = 10000;
                    }

                    new Timer().schedule(
                            new TimerTask() {
                                @Override
                                public void run() {
                                    //sharedParameters.allSettings.subTabSettings.updateSubTabsUI(toolName);
                                    sharedParameters.allSettings.subTabSettings.loadSettings(toolName);
                                    sharedParameters.allSettings.subTabSettings.saveSettings(toolName);
                                    set_isUpdateInProgress(false);
                                }
                            },
                            delay
                    );
                }
            }
        };

        // Loading all the tabs

        JTabbedPane subTabbedPane = sharedParameters.get_toolTabbedPane(toolName);

        targetComponent.addPropertyChangeListener("indexForTabComponent", tabPropertyChangeListener);

        if (subTabbedPane != null) {
            addSubTabsListener(subTabbedPane, toolName);
        }else{
            // when Burp Suite is loaded for the first time, Repeater and Intruder tabs are empty in the latest versions rather than having one tab
            // This is to address the issue of component change when the first tab is being created
            targetComponent.addComponentListener(new ComponentListener() {
                @Override
                public void componentResized(ComponentEvent e) {}

                @Override
                public void componentMoved(ComponentEvent e) {}

                @Override
                public void componentShown(ComponentEvent e) {}

                @Override
                public void componentHidden(ComponentEvent e) {
                    new java.util.Timer().schedule(
                            new java.util.TimerTask() {
                                @Override
                                public void run() {
                                    // This will be triggered when Burp creates items in Repeater or Intruder
                                    BurpUITools.MainTabs toolName = BurpUITools.getMainTabsObjFromString(sharedParameters.get_rootTabbedPane().getTitleAt(sharedParameters.get_rootTabbedPane().indexOfComponent(((Component) e.getSource()).getParent())));
                                    JTabbedPane subTabbedPane = sharedParameters.get_toolTabbedPane(toolName);
                                    if (subTabbedPane != null) {
                                        if(subTabbedPane.getPropertyChangeListeners("tabPropertyChangeListener").length==0)
                                            subTabbedPane.addPropertyChangeListener("indexForTabComponent", tabPropertyChangeListener);

                                        addSubTabsListener(subTabbedPane, toolName);

                                        // as there is no other getComponentListeners by default, we can remove them all
                                        for (ComponentListener cl : subTabbedPane.getComponentListeners()) {
                                            subTabbedPane.removeComponentListener(cl);
                                        }
                                    }
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

    private void addSubTabsListener(JTabbedPane subTabbedPane, BurpUITools.MainTabs toolName){
        if(sharedParameters.allSubTabContainerHandlers.get(toolName) == null || sharedParameters.allSubTabContainerHandlers.get(toolName).size() != subTabbedPane.getTabCount()-1){
            ArrayList<SubTabContainerHandler> subTabContainerHandlers = new ArrayList<>();
            for (Component subTabComponent : subTabbedPane.getComponents()) {
                int subTabIndex = subTabbedPane.indexOfComponent(subTabComponent);
                if (subTabIndex == -1)
                    continue;
                SubTabContainerHandler subTabContainerHandler = new SubTabContainerHandler(sharedParameters, subTabbedPane, subTabIndex, false);
                subTabContainerHandlers.add(subTabContainerHandler);
            }

            // this for dotdotdot tab!
            SubTabContainerHandler tempDotDotDotSubTabContainerHandler = new SubTabContainerHandler(sharedParameters, subTabbedPane, subTabbedPane.getTabCount()-1, true);
            if (tempDotDotDotSubTabContainerHandler != null && !subTabContainerHandlers.contains(tempDotDotDotSubTabContainerHandler)) {
                // we have a new tab
                tempDotDotDotSubTabContainerHandler.addSubTabWatcher();
                subTabContainerHandlers.add(tempDotDotDotSubTabContainerHandler);
            }

            sharedParameters.allSubTabContainerHandlers.put(toolName, subTabContainerHandlers);
        }

        subTabbedPane.addMouseListener(new MouseAdapterExtensionHandler(mouseEventConsumer, MouseEvent.MOUSE_RELEASED));

        //Defining shortcuts for search in tab titles: ctrl+shift+f , F3, shift+F3
        if(_isShortcutEnabled) {
            clearInputMap(subTabbedPane);
            subTabsShortcutMappings.forEach((k,v) -> subTabbedPane.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(
                    KeyStroke.getKeyStroke(k), v));

            subTabbedPane.getActionMap().put("ShowMenu", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabActions.showPopupMenu(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("FindTabs", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabActions.defineRegExPopupForSearchAndJump(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("NextFind", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabActions.searchInTabTitlesAndJump(sharedParameters, e, true);
                }
            });
            subTabbedPane.getActionMap().put("PreviousFind", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabActions.searchInTabTitlesAndJump(sharedParameters, e, false);
                }
            });
            subTabbedPane.getActionMap().put("FirstTab", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabActions.jumpToFirstTab(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("LastTab", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabActions.jumpToLastTab(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("PreviousTab", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabActions.jumpToPreviousTab(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("NextTab", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabActions.jumpToNextTab(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("PreviouslySelectedTab", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabActions.jumpToPreviosulySelectedTab(sharedParameters, e);
                }
            });
            subTabbedPane.getActionMap().put("NextlySelectedTab", new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    SubTabActions.jumpToNextlySelectedTab(sharedParameters, e);
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

        // Burp has changed something in the UI so we need this if condition to support older versions
        JComponent targetComponent;

        if(tabComponent.getMouseListeners().length > 0){
            targetComponent = (JComponent) tabComponent;
        }else{
            //tabComponent.getComponentAt(0,0).addMouseListener(new SubTabClickHandler(this.mouseEventConsumer));
            targetComponent = (JComponent) tabComponent.getComponentAt(0,0);
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

        // There is no bindings on these items so it can be cleared
        if(_isShortcutEnabled) {
            clearInputMap(targetComponent);
        }
    }

    private void clearInputMap(JComponent jc){
        subTabsShortcutMappings.forEach((k,v) -> jc.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(
                KeyStroke.getKeyStroke(k), "none"));
    }
    private synchronized void set_isUpdateInProgress(boolean _isUpdateInProgress) {
        this._isUpdateInProgress = _isUpdateInProgress;
    }

    private synchronized boolean get_isUpdateInProgress() {
        return this._isUpdateInProgress;
    }
}
