// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.uimodifiers.subtabs;

import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.burp.sharpener.objects.TabFeaturesObject;
import com.irsdl.burp.sharpener.objects.TabFeaturesObjectStyle;

import javax.swing.*;
import java.awt.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.ArrayList;
import java.util.Collections;

public class SubTabContainerHandler {
    public JTabbedPane parentTabbedPane;
    public Container currentTab;
    public Component currentTabLabel;
    public Component currentTabCloseButton;
    public Boolean hasChanged = false;
    public ArrayList<String> titleHistory = new ArrayList<>(); // shouldn't have more than 2 items but just in case!
    public ArrayList<Integer> tabIndexHistory = new ArrayList<>();
    public BurpUITools.MainTabs currentToolTab;

    private final SubTabContainerHandler instance;
    private final SharpenerSharedParameters sharedParameters;
    private ArrayList<String> cachedTabTitles;
    private boolean titleEditInProgress = false;
    private String beforeManualEditTabTitle = "";
    private Color beforeManualEditTabColor;
    private PropertyChangeListener subTabPropertyChangeListener;
    private boolean isFromSetColor = false;

    public SubTabContainerHandler(SharpenerSharedParameters sharedParameters, JTabbedPane tabbedPane, int tabIndex) {
        this.instance = this;
        this.sharedParameters = sharedParameters;
        this.parentTabbedPane = tabbedPane;
        Component currentTabTemp = tabbedPane.getTabComponentAt(tabIndex);
        if (!(currentTabTemp instanceof Container)) return; // this is not a container, so it is not useful for us

        // to find whether this subtab is in repeater or intruder:
        String toolTabName = "";
        Component parentOfTabbedPane = tabbedPane.getParent();
        if (parentOfTabbedPane instanceof JTabbedPane) {
            JTabbedPane parentTabbedPane = ((JTabbedPane) parentOfTabbedPane);
            toolTabName = parentTabbedPane.getTitleAt(parentTabbedPane.indexOfComponent(tabbedPane));

        } else if (parentOfTabbedPane instanceof JPanel) {
            // it's being detached! who does that?! :p
            JPanel parentTabbedPane = ((JPanel) parentOfTabbedPane);
            toolTabName = ((JFrame) parentTabbedPane.getRootPane().getParent()).getTitle().replace("Burp ", "");
        }

        currentToolTab = BurpUITools.getMainTabsObjFromString(toolTabName);

        if(currentToolTab == BurpUITools.MainTabs.None){
            // this is the new changes introduce by burp 2022.1 so we need this code now
            int currentTabToolIndex = sharedParameters.get_rootTabbedPane().indexOfComponent(tabbedPane.getParent());
            toolTabName = sharedParameters.get_rootTabbedPane().getTitleAt(currentTabToolIndex);
        }

        currentToolTab = BurpUITools.getMainTabsObjFromString(toolTabName);

        this.currentTab = (Container) currentTabTemp;
        this.currentTabLabel = currentTab.getComponent(0);

        if (tabIndex != tabbedPane.getTabCount() - 1)
            currentTabCloseButton = currentTab.getComponent(1); // to get the X button

        // to keep history of previous titles
        if (titleHistory.size() == 0)
            titleHistory.add(getTabTitle());

        if (tabIndexHistory.size() == 0)
            tabIndexHistory.add(tabIndex);

        addSubTabWatcher();
    }

    public void addSubTabWatcher() {
        // this.currentTabLabel.getPropertyChangeListeners().length is 2 by default in this case ... Burp Suite may change this and break my extension :s
        if (subTabPropertyChangeListener == null && isValid() && this.currentTabLabel.getPropertyChangeListeners().length < 3) {
            subTabPropertyChangeListener = new PropertyChangeListener() {
                @Override
                public void propertyChange(PropertyChangeEvent evt) {
                    if (evt.getPropertyName().equalsIgnoreCase("editable")) {
                        if (evt.getSource().getClass().equals(currentTabLabel.getClass())) {
                            if (!titleEditInProgress) {
                                if ((boolean) evt.getNewValue() == true) {
                                    titleEditInProgress = true;
                                    beforeManualEditTabTitle = getTabTitle();
                                    beforeManualEditTabColor = getColor();
                                }
                            } else {
                                if ((boolean) evt.getNewValue() == false) {
                                    titleEditInProgress = false;
                                    new java.util.Timer().schedule(
                                            new java.util.TimerTask() {
                                                @Override
                                                public void run() {
                                                    setColor(beforeManualEditTabColor);
                                                    if (!beforeManualEditTabTitle.equals(getTabTitle())) {
                                                        // title has changed manually
                                                        sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(instance);
                                                    }
                                                    sharedParameters.allSettings.subTabSettings.loadSettings();
                                                }
                                            },
                                            500
                                    );
                                }
                            }
                        }

                    }else if (evt.getPropertyName().equalsIgnoreCase("disabledTextColor")) {
                        boolean isFromSetToDefault = false;
                        Color newColor = (Color) evt.getNewValue();

                        if(newColor!=null && Integer.toHexString(newColor.getRGB()).substring(2) == "010101"){
                            isFromSetToDefault = true;
                        }

                        loadDefaultSetting();

                        if(!isFromSetColor && !isFromSetToDefault){
                            if(newColor!=null && newColor.equals(sharedParameters.defaultSubTabObject.getColor())){
                                // we have a case for auto tab colour change which we want to avoid
                                setColor((Color) evt.getOldValue());
                            }
                        }else if(newColor==null || isFromSetToDefault){
                            setColor(sharedParameters.defaultSubTabObject.getColor());
                        }
                        isFromSetColor = false;
                    }
                }
            };
            this.currentTabLabel.addPropertyChangeListener(subTabPropertyChangeListener);
        } else if (this.currentTabLabel.getPropertyChangeListeners().length == 3) {
            subTabPropertyChangeListener = this.currentTabLabel.getPropertyChangeListeners()[2];
        }
    }

    public void removeSubTabWatcher() {
        if (subTabPropertyChangeListener != null) {
            this.currentTabLabel.removePropertyChangeListener(subTabPropertyChangeListener);
        }
    }

    public TabFeaturesObject getTabFeaturesObject() {
        return new TabFeaturesObject(getTabIndex(), getTabTitle(), getFontName(), getFontSize(), isBold(), isItalic(), getVisibleCloseButton(), getColor());
    }

    public TabFeaturesObjectStyle getTabFeaturesObjectStyle() {
        return getTabFeaturesObject().getStyle();
    }

    public void updateByTabFeaturesObject(TabFeaturesObject tabFeaturesObject) {
        this.setTabTitle(tabFeaturesObject.title);
        this.updateByTabFeaturesObjectStyle(tabFeaturesObject.getStyle());
    }

    public void updateByTabFeaturesObjectStyle(TabFeaturesObjectStyle tabFeaturesObjectStyle) {
        this.setFontName(tabFeaturesObjectStyle.fontName);
        this.setFontSize(tabFeaturesObjectStyle.fontSize);
        this.setBold(tabFeaturesObjectStyle.isBold);
        this.setItalic(tabFeaturesObjectStyle.isItalic);
        this.setVisibleCloseButton(tabFeaturesObjectStyle.isCloseButtonVisible);
        this.setColor(tabFeaturesObjectStyle.getColorCode());
    }

    public boolean isValid() {
        boolean result = true;
        if (parentTabbedPane == null || getTabIndex() == -1 || currentTab == null || currentTabLabel == null ||
                currentTabCloseButton == null) {
            result = false;
        }
        return result;
    }

    private void loadDefaultSetting() {
        // To set the defaultSubTabObject parameter which keeps default settings of a normal tab
        if (sharedParameters.defaultSubTabObject == null) {
            for (BurpUITools.MainTabs tool : sharedParameters.subTabWatcherSupportedTabs) {
                if (sharedParameters.supportedTools_SubTabs.get(tool) != null) {
                    JTabbedPane toolTabbedPane = sharedParameters.get_toolTabbedPane(tool);
                    if (toolTabbedPane != null) {
                        for (Component tabComponent : toolTabbedPane.getComponents()) {
                            int subTabIndex = toolTabbedPane.indexOfComponent(tabComponent);
                            if (subTabIndex == -1)
                                continue;
                            sharedParameters.defaultSubTabObject = new SubTabContainerHandler(sharedParameters, toolTabbedPane, toolTabbedPane.getTabCount() - 1);
                            break;
                        }
                    }
                }
                if (sharedParameters.defaultSubTabObject != null)
                    break;
            }
        }
    }

    public boolean isDefault() {
        boolean result = false;
        loadDefaultSetting();
        if (getTabIndex() == parentTabbedPane.getTabCount() - 1 || sharedParameters.defaultSubTabObject.getTabFeaturesObjectStyle().equals(getTabFeaturesObjectStyle())) {
            result = true;
        }
        return result;
    }

    public void setToDefault() {
        loadDefaultSetting();
        // in order to set the right colour when reset to default is used, we need to use a special colour to detect this event
        // this is because Burp does use the default colour when an item is changed - we have a workaround for that but
        // the workaround stops reset to default to change the colour as well so we need another workaround!!!
        TabFeaturesObjectStyle tfosDefault = sharedParameters.defaultSubTabObject.getTabFeaturesObjectStyle();
        tfosDefault.setColorCode(Color.decode("#010101"));
        updateByTabFeaturesObjectStyle(tfosDefault);
    }

    public boolean isCurrentTitleUnique() {
        boolean result = true;

        if (cachedTabTitles == null || !titleHistory.get(titleHistory.size() - 1).equals(getTabTitle())) {
            cachedTabTitles = new ArrayList<>();
            for (int index = 0; index < parentTabbedPane.getTabCount() - 1; index++) {
                cachedTabTitles.add(parentTabbedPane.getTitleAt(index));
            }
            if (!titleHistory.get(titleHistory.size() - 1).equals(getTabTitle()))
                titleHistory.add(getTabTitle());
        }

        if (Collections.frequency(cachedTabTitles, getTabTitle()) > 1)
            result = false;

        return result;
    }

    public boolean isNewTitleUnique(String newTitle) {
        boolean result = true;

        if (cachedTabTitles == null || !titleHistory.get(titleHistory.size() - 1).equals(getTabTitle())) {
            cachedTabTitles = new ArrayList<>();
            for (int index = 0; index < parentTabbedPane.getTabCount() - 1; index++) {
                cachedTabTitles.add(parentTabbedPane.getTitleAt(index));
            }
            /*
            if (!titleHistory.get(titleHistory.size() - 1).equals(getTabTitle()))
                titleHistory.add(getTabTitle());

             */
        }

        if (Collections.frequency(cachedTabTitles, newTitle) > 0)
            result = false;

        return result;
    }

    public int getTabIndex() {
        int subTabIndex = parentTabbedPane.indexOfTabComponent(currentTab);

        if (tabIndexHistory.size() == 0 || subTabIndex != tabIndexHistory.get(tabIndexHistory.size() - 1)) {
            tabIndexHistory.add(subTabIndex);
        }

        return subTabIndex;
    }

    public String getTabTitle() {
        return parentTabbedPane.getTitleAt(getTabIndex());
    }

    public void setTabTitle(String title) {
        if (isValid() && !title.isEmpty()) {
            hasChanged = true;

            if (titleHistory.size() == 0 || !titleHistory.get(titleHistory.size() - 1).equals(title))
                titleHistory.add(title);

            parentTabbedPane.setTitleAt(getTabIndex(), title);
        }
    }

    public void setFont(Font newFont) {
        if (isValid()) {
            hasChanged = true;
            currentTabLabel.setFont(newFont);
        }
    }

    public Font getFont() {
        return currentTabLabel.getFont();
    }

    public void setFontName(String name) {
        setFont(new Font(name, getFont().getStyle(), getFont().getSize()));
    }

    public String getFontName() {
        return getFont().getFamily();
    }

    public void setFontSize(float size) {
        setFont(getFont().deriveFont(size));
    }

    public float getFontSize() {
        return getFont().getSize();
    }

    public void toggleBold() {
        setFont(getFont().deriveFont(getFont().getStyle() ^ Font.BOLD));
    }

    public void setBold(boolean shouldBeBold) {
        if (shouldBeBold && !isBold()) {
            toggleBold();
        } else if (!shouldBeBold && isBold()) {
            toggleBold();
        }
    }

    public boolean isBold() {
        return getFont().isBold();
    }

    public void toggleItalic() {
        setFont(getFont().deriveFont(getFont().getStyle() ^ Font.ITALIC));
    }

    public void setItalic(boolean shouldBeItalic) {
        if (shouldBeItalic && !isItalic()) {
            toggleItalic();
        } else if (!shouldBeItalic && isItalic()) {
            toggleItalic();
        }
    }

    public boolean isItalic() {
        return getFont().isItalic();
    }

    public Color getColor() {
        return currentTabLabel.getForeground();
    }

    public void setColor(Color color) {
        if (isValid()) {
            isFromSetColor = true;
            hasChanged = true;
            parentTabbedPane.setBackgroundAt(getTabIndex(), color);
        }
    }

    public void showCloseButton() {
        if (isValid()) {
            hasChanged = true;
            currentTabCloseButton.setVisible(true);
        }
    }

    public void hideCloseButton() {
        if (isValid()) {
            hasChanged = true;
            currentTabCloseButton.setVisible(false);
        }
    }

    public void setVisibleCloseButton(boolean isVisible) {
        if (isVisible) {
            showCloseButton();
        } else {
            hideCloseButton();
        }
    }

    public boolean getVisibleCloseButton() {
        if (!isValid()) {
            return true;
        }
        return currentTabCloseButton.isVisible();
    }

    @Override
    public boolean equals(Object o) {
        boolean result = false;
        if (isValid()) {
            if (o instanceof SubTabContainerHandler) {
                SubTabContainerHandler temp = (SubTabContainerHandler) o;
                result = temp.currentTab == this.currentTab;
            } else if (o instanceof Container) {
                Container temp = (Container) o;
                result = temp == this.currentTab;
            }
        } else {
            if (o instanceof SubTabContainerHandler) {
                SubTabContainerHandler temp = (SubTabContainerHandler) o;
                result = temp.tabIndexHistory.get(temp.tabIndexHistory.size() - 1) == this.tabIndexHistory.get(this.tabIndexHistory.size() - 1);
            }
        }
        return result;
    }
}
