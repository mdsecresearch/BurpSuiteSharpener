// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.uiModifiers.subTabs;

import com.formdev.flatlaf.ui.FlatTabbedPaneUI;
import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.burp.sharpener.objects.TabFeaturesObjectStyle;
import com.irsdl.generic.*;
import org.apache.commons.lang3.StringUtils;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.colorchooser.AbstractColorChooserPanel;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.MouseEvent;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.regex.Pattern;

public class SubTabActions {
    public static void tabClicked(final MouseEvent event, SharpenerSharedParameters sharedParameters) {
        SubTabContainerHandler subTabContainerHandler = null;
        if (event.getComponent() instanceof JTabbedPane) {
                /*
                // this was useful when we did not know which tab has been selected but in Burp Suite a tab will be selected upon a click so we can find the index that way
                int tabIndex = tabbedPane.getUI().tabForCoordinate(tabbedPane, event.getX(), event.getY());
                if (tabIndex < 0 || tabIndex > tabbedPane.getTabCount() - 1) return;
                */

            subTabContainerHandler = getSubTabContainerHandlerFromEvent(sharedParameters, event);

            if(subTabContainerHandler == null)
                sharedParameters.printlnError("Object has not been loaded yet, try in a few seconds.");

            if (subTabContainerHandler == null || (!subTabContainerHandler.isValid()&&!subTabContainerHandler.isDotDotDotTab())) return;

            jumpToTabIndex(sharedParameters, subTabContainerHandler, subTabContainerHandler.getTabIndex());
        }

        if (SwingUtilities.isMiddleMouseButton(event) || event.isAltDown() || ((event.getModifiersEx() & ActionEvent.ALT_MASK) == ActionEvent.ALT_MASK)) {
            boolean isCTRL_Key = (event.getModifiersEx() & ActionEvent.CTRL_MASK) == ActionEvent.CTRL_MASK || event.isControlDown();
            // Middle key is like the Alt key!
            //boolean isALT_Key = (event.getModifiers() & ActionEvent.ALT_MASK) == ActionEvent.ALT_MASK;
            boolean isSHIFT_Key = (event.getModifiersEx() & ActionEvent.SHIFT_MASK) == ActionEvent.SHIFT_MASK || event.isShiftDown();

            int maxSize = 40;
            int minSize = 10;
            if (!isCTRL_Key && !isSHIFT_Key) {
                // showing popup menu
                showPopupMenu(sharedParameters, subTabContainerHandler, event);
            } else if (isCTRL_Key && !isSHIFT_Key) {
                // Make it bigger and bold when middle click + ctrl
                if (subTabContainerHandler.getFontSize() < maxSize) {
                    if (!subTabContainerHandler.isBold())
                        subTabContainerHandler.toggleBold(false);
                    subTabContainerHandler.setFontSize(subTabContainerHandler.getFontSize() + 2, false);
                    subTabContainerHandler.hideCloseButton(false);
                }
            } else if (isCTRL_Key) {
                // Make it smaller but bold when middle click + ctrl + shift
                if (subTabContainerHandler.getFontSize() > minSize) {
                    if (!subTabContainerHandler.isBold())
                        subTabContainerHandler.toggleBold(false);
                    subTabContainerHandler.setFontSize(subTabContainerHandler.getFontSize() - 2, false);
                    subTabContainerHandler.hideCloseButton(false);
                }
            } else{
                // middle click with shift: should make it red and big and bold
                TabFeaturesObjectStyle tabFeaturesObjectStyle = new TabFeaturesObjectStyle("High: Red, Big, and Bold", "Arial", 18, true, false, false, Color.decode("#f71414"));
                subTabContainerHandler.updateByTabFeaturesObjectStyle(tabFeaturesObjectStyle, false);
            }

            if (subTabContainerHandler.getHasChanges()) {
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(subTabContainerHandler);
            }
        }
    }

    public static void addMouseWheelToJTabbedPane(SharpenerSharedParameters sharedParameters, BurpUITools.MainTabs currentToolTab, boolean isLastOneSelectable) {
        // from https://stackoverflow.com/questions/38463047/use-mouse-to-scroll-through-tabs-in-jtabbedpane

        MouseWheelListener mwl = new MouseWheelListener() {
            @Override
            public void mouseWheelMoved(MouseWheelEvent e) {
                JTabbedPane tabbedPane = (JTabbedPane) e.getSource();
                // works with version 2022.1.1 - not tested in the previous versions!
                int currentSelection = tabbedPane.getSelectedIndex();
                SubTabContainerHandler subTabContainerHandler = getSubTabContainerHandlerFromSharedParameters(sharedParameters, tabbedPane, currentSelection);

                if (e.isControlDown()) {
                    float currentFontSize = subTabContainerHandler.getFontSize();

                    if (e.getWheelRotation() < 0) {
                        //scrolled up
                        if(currentFontSize<=36){
                            subTabContainerHandler.setFontSize(currentFontSize+2, false);
                        }
                    } else {
                        //scrolled down
                        if(currentFontSize>=12) {
                            subTabContainerHandler.setFontSize(currentFontSize-2, false);
                        }
                    }

                    if (subTabContainerHandler.getHasChanges()) {
                        sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(subTabContainerHandler);
                    }
                }else if(e.isAltDown()){    // experiment here




                }else if (e.isAltDown() && 1==2) { // mw+alt has been disabled as moved tabs won't be saved in the project file!
                    JComponent[] components = new JComponent[2];
                    JComponent[] tabComponents = new JComponent[2];
                    components[0] = (JComponent) tabbedPane.getSelectedComponent();
                    tabComponents[0] = (JComponent) tabbedPane.getTabComponentAt(currentSelection);


                    if (e.getWheelRotation() > 0) {
                        //scrolled down
                        if(currentSelection < tabbedPane.getTabCount() - 2){
                            components[1] = (JComponent) tabbedPane.getComponentAt(currentSelection+1);
                            tabComponents[1] = (JComponent) tabbedPane.getTabComponentAt(currentSelection+1);

//*
                            try{
                                tabbedPane.remove(currentSelection+1);
                            }catch(Exception err){

                            }

                            try{
                                tabbedPane.remove(currentSelection);
                            }catch(Exception err){

                            }

                            try{
                                tabbedPane.add(components[1], currentSelection);

                            }catch(Exception err){

                            }finally {
                                tabbedPane.setTabComponentAt(currentSelection, tabComponents[1]);
                            }

                            try{
                                tabbedPane.add(components[0], currentSelection+1);
                            }catch(Exception err){

                            }finally {
                                tabbedPane.setTabComponentAt(currentSelection+1, tabComponents[0]);
                            }
//*/

                            /*

                            tabbedPane.add(components[1], currentSelection);
                            tabbedPane.add(components[0], currentSelection+1);

                             */

                            // Null Exception from Burp modules!!! :'(
                            //tabbedPane.add(((JComponent) tabbedPane.getTabComponentAt(currentSelection)).getComponent(0), currentSelection+1);
                            //tabbedPane.add(tabbedPane.getTabComponentAt(currentSelection+1), currentSelection);

                            // Null Exception from Burp modules!!! :'(
                            //tabbedPane.insertTab(((JTextField)tabComponents[0].getComponent(0)).getText(),null,components[0],"",currentSelection+1);
                            //tabbedPane.insertTab(((JTextField)tabComponents[1].getComponent(0)).getText(),null,components[1],"",currentSelection);
/*
                            try{
                                tabbedPane.setComponentAt(currentSelection, components[1]);
                            }catch(Exception err){

                            }finally {
                                tabbedPane.setTabComponentAt(currentSelection, tabComponents[1]);
                            }

                            try{
                                tabbedPane.setComponentAt(currentSelection+1, components[0]);
                            }catch(Exception err){

                            }finally {
                                tabbedPane.setTabComponentAt(currentSelection+1, tabComponents[0]);
                            }


*/
                            jumpToTabIndex(sharedParameters,subTabContainerHandler,currentSelection+1);


                            tabbedPane.revalidate();
                            tabbedPane.repaint();
                        }
                    } else{
                        //scrolled up
                        if(currentSelection > 0){
                            components[1] = (JComponent) tabbedPane.getComponentAt(currentSelection-1);
                            tabComponents[1] = (JComponent) tabbedPane.getTabComponentAt(currentSelection-1);
//*
                            try{
                                tabbedPane.remove(currentSelection);
                            }catch(Exception err){

                            }

                            try{
                                tabbedPane.remove(currentSelection-1);
                            }catch(Exception err){

                            }

                            try{
                                tabbedPane.add(components[0], currentSelection-1);
                            }catch(Exception err){

                            }finally {
                                tabbedPane.setTabComponentAt(currentSelection-1, tabComponents[0]);
                            }

                            try{
                                tabbedPane.add(components[1], currentSelection);
                            }catch(Exception err){

                            }finally {
                                tabbedPane.setTabComponentAt(currentSelection, tabComponents[1]);
                            }


                            // */



                            // Null Exception from Burp modules!!! :'(
                            //tabbedPane.add(((JComponent) tabbedPane.getTabComponentAt(currentSelection)).getComponent(0), currentSelection+1);
                            //tabbedPane.add(tabbedPane.getTabComponentAt(currentSelection+1), currentSelection);

                            // Null Exception from Burp modules!!! :'(
                            //tabbedPane.insertTab(((JTextField)tabComponents[0].getComponent(0)).getText(),null,components[0],"",currentSelection+1);
                            //tabbedPane.insertTab(((JTextField)tabComponents[1].getComponent(0)).getText(),null,components[1],"",currentSelection);
/*
                            try{
                                tabbedPane.setComponentAt(currentSelection, components[1]);
                            }catch(Exception err){

                            }finally {
                                tabbedPane.setTabComponentAt(currentSelection, tabComponents[1]);
                            }

                            try{
                                tabbedPane.setComponentAt(currentSelection-1, components[0]);
                            }catch(Exception err){

                            }finally {
                                tabbedPane.setTabComponentAt(currentSelection-1, tabComponents[0]);
                            }

 */





                            jumpToTabIndex(sharedParameters,subTabContainerHandler,currentSelection-1);


                            tabbedPane.revalidate();
                            tabbedPane.repaint();
                        }
                    }





                }else{
                    int offset = 0;
                    if (!isLastOneSelectable)
                        offset = 1;

                    int units = e.getWheelRotation();
                    int oldIndex = tabbedPane.getSelectedIndex();
                    int newIndex = oldIndex + units;
                    int chosenOne = newIndex;
                    if (newIndex < 0)
                        chosenOne = 0;
                    else if (newIndex >= tabbedPane.getTabCount() - offset)
                        chosenOne=tabbedPane.getTabCount() - 1 - offset;

                    while(!tabbedPane.isEnabledAt(chosenOne)){
                        if(units>0){
                            //scroll down
                            chosenOne++;
                        }else{
                            //scroll up
                            chosenOne--;
                        }

                        if (chosenOne < 0 || chosenOne >= tabbedPane.getTabCount() - offset){
                            chosenOne = oldIndex;
                            break;
                        }
                    }
                    jumpToTabIndex(sharedParameters,subTabContainerHandler,chosenOne);
                }

            }
        };
        sharedParameters.get_toolTabbedPane(currentToolTab).addMouseWheelListener(mwl);
    }

    public static void removeMouseWheelFromJTabbedPane(SharpenerSharedParameters sharedParameters, BurpUITools.MainTabs currentToolTab, boolean onlyRemoveLast) {
        MouseWheelListener[] mwlArr = sharedParameters.get_toolTabbedPane(currentToolTab).getMouseWheelListeners();
        for (int i = mwlArr.length - 1; i >= 0; i--) {
            sharedParameters.get_toolTabbedPane(currentToolTab).removeMouseWheelListener(mwlArr[i]);
            if (onlyRemoveLast) {
                break;
            }
        }
    }

    private static  void setNotificationMenuMessage(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler, JMenuItem notificationMenuItem, String message){
        if(sharedParameters.isFiltered(currentSubTabContainerHandler.currentToolTab)){

            if(!currentSubTabContainerHandler.getVisible())
            {
                message = "Filter: ON ("+sharedParameters.getHiddenSubTabsCount(currentSubTabContainerHandler.currentToolTab)+
                        " hidden tabs) | THIS IS A HIDDEN TAB | " + message;
            }else{
                message = "Filter: ON ("+sharedParameters.getHiddenSubTabsCount(currentSubTabContainerHandler.currentToolTab)+
                        " hidden tabs) | " + message;
            }

        }else{
            message = "Filter: OFF | " + message;
        }
        notificationMenuItem.setText(message);
    }

    private static JPopupMenu createPopupMenu(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler) {
        JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem notificationMenuItem = new JMenuItem();
        notificationMenuItem.setFont(notificationMenuItem.getFont().deriveFont(notificationMenuItem.getFont().getStyle() ^ Font.BOLD));
        setNotificationMenuMessage(sharedParameters, currentSubTabContainerHandler, notificationMenuItem, "Tab Title: " + currentSubTabContainerHandler.getTabTitle());

        notificationMenuItem.setEnabled(false);
        popupMenu.add(notificationMenuItem);
        popupMenu.addSeparator();

        if(!currentSubTabContainerHandler.isDotDotDotTab()) {
            JMenuItem pasteStyleMenu = new JMenuItem("Paste Style");
            if (sharedParameters.copiedTabFeaturesObjectStyle == null) {
                pasteStyleMenu.setEnabled(false);
            }
            pasteStyleMenu.addActionListener(e -> {
                if (sharedParameters.copiedTabFeaturesObjectStyle != null) {
                    currentSubTabContainerHandler.updateByTabFeaturesObjectStyle(sharedParameters.copiedTabFeaturesObjectStyle, true);
                    sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
                    sharedParameters.printDebugMessage("Style pasted...");
                }
            });
            popupMenu.add(pasteStyleMenu);

            JMenuItem copyStyleMenu = new JMenuItem("Copy Style");
            //if (currentSubTabContainerHandler.isDefault())
            //    copyStyleMenu.setEnabled(false);
            copyStyleMenu.addActionListener(e -> {
                sharedParameters.copiedTabFeaturesObjectStyle = currentSubTabContainerHandler.getTabFeaturesObjectStyle();
                sharedParameters.printDebugMessage("Style copied...");
            });
            popupMenu.add(copyStyleMenu);


            JMenuItem defaultProfile = new JMenuItem("Reset to Default");
            defaultProfile.addActionListener(e -> {
                currentSubTabContainerHandler.setToDefault(true);
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
            });
            if (currentSubTabContainerHandler.isDefault())
                defaultProfile.setEnabled(false);
            popupMenu.add(defaultProfile);

            JMenu profileMenu = new JMenu("Predefined Styles");

            JMenuItem highProfile = new JMenuItem("High: Red, Big, and Bold");
            highProfile.addActionListener(e -> {
                TabFeaturesObjectStyle tabFeaturesObjectStyle = new TabFeaturesObjectStyle("High: Red, Big, and Bold", "Arial", 18, true, false, false, Color.decode("#f71414"));
                currentSubTabContainerHandler.updateByTabFeaturesObjectStyle(tabFeaturesObjectStyle, true);
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
            });
            profileMenu.add(highProfile);

            JMenuItem mediumProfile = new JMenuItem("Medium: Orange, Big, and Bold");
            mediumProfile.addActionListener(e -> {
                TabFeaturesObjectStyle tabFeaturesObjectStyle = new TabFeaturesObjectStyle("Medium: Orange, Big, and Bold", "Arial", 18, true, false, false, Color.decode("#ff7e0d"));
                currentSubTabContainerHandler.updateByTabFeaturesObjectStyle(tabFeaturesObjectStyle, true);
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
            });
            profileMenu.add(mediumProfile);

            JMenuItem lowProfile = new JMenuItem("Low: Yellow, Bold");
            lowProfile.addActionListener(e -> {
                TabFeaturesObjectStyle tabFeaturesObjectStyle = new TabFeaturesObjectStyle("Low: Yellow, Bold", "Arial", 14, true, false, false, Color.decode("#fadc00"));
                currentSubTabContainerHandler.updateByTabFeaturesObjectStyle(tabFeaturesObjectStyle, true);
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
            });
            profileMenu.add(lowProfile);

            JCheckBoxMenuItem infoProfile = new JCheckBoxMenuItem("Info: Green, Bold, Italic");
            infoProfile.addActionListener(e -> {
                TabFeaturesObjectStyle tabFeaturesObjectStyle = new TabFeaturesObjectStyle("Info: Green, Bold, Italic", "Arial", 14, true, true, false, Color.decode("#0d9e1e"));
                currentSubTabContainerHandler.updateByTabFeaturesObjectStyle(tabFeaturesObjectStyle, true);
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
            });
            profileMenu.add(infoProfile);

            popupMenu.add(profileMenu);

            JMenu customStyleMenu = new JMenu("Custom Style");
            JCheckBoxMenuItem closeButtonMenuItem = new JCheckBoxMenuItem("Remove Close Button");
            closeButtonMenuItem.addActionListener(e -> {
                currentSubTabContainerHandler.setVisibleCloseButton(!closeButtonMenuItem.isSelected(), true);
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
            });
            closeButtonMenuItem.setSelected(!currentSubTabContainerHandler.getVisibleCloseButton());
            customStyleMenu.add(closeButtonMenuItem);

            JMenu fontNameMenu = new JScrollMenu("Font Name");
            String[] fonts = GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames();

            for (String font : fonts) {
                JCheckBoxMenuItem fontnameItem = new JCheckBoxMenuItem(font);
                fontnameItem.setSelected(font.equalsIgnoreCase(currentSubTabContainerHandler.getFontName()));
                fontnameItem.addActionListener(e -> {
                    currentSubTabContainerHandler.setFontName(font, true);
                    sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);

                });
                fontNameMenu.add(fontnameItem);
            }
            customStyleMenu.add(fontNameMenu);

            JMenu fontSizeMenu = new JMenu("Font Size");
            float minFontSize = 10, maxFontSize = 40;
            for (float fontSize = minFontSize; fontSize < maxFontSize; fontSize += 2) {
                JCheckBoxMenuItem sizeItem = new JCheckBoxMenuItem(fontSize + "");
                sizeItem.setSelected(currentSubTabContainerHandler.getFontSize() == fontSize);
                float finalFontSize = fontSize;
                sizeItem.addActionListener(e -> {
                    currentSubTabContainerHandler.setFontSize(finalFontSize, true);
                    sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
                });
                fontSizeMenu.add(sizeItem);
            }
            customStyleMenu.add(fontSizeMenu);

            JCheckBoxMenuItem boldMenu = new JCheckBoxMenuItem("Bold");
            boldMenu.setSelected(currentSubTabContainerHandler.isBold());
            boldMenu.addActionListener(e -> {
                currentSubTabContainerHandler.toggleBold(true);
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
            });
            customStyleMenu.add(boldMenu);

            JCheckBoxMenuItem italicMenu = new JCheckBoxMenuItem("Italic");
            italicMenu.setSelected(currentSubTabContainerHandler.isItalic());
            italicMenu.addActionListener(e -> {
                currentSubTabContainerHandler.toggleItalic(true);
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
            });
            customStyleMenu.add(italicMenu);

            JMenuItem colorMenu = new JMenuItem("Set Foreground Color");
            colorMenu.addActionListener(e -> {
                JColorChooser colorChooser = new JColorChooser();
                // we only want to keep the Swatches panel
                AbstractColorChooserPanel[] panels = colorChooser.getChooserPanels();
                for (AbstractColorChooserPanel p : panels) {
                    String displayName = p.getDisplayName();
                    switch (displayName) {
                        //case "RGB":
                        case "HSL", "HSV", "CMYK" -> colorChooser.removeChooserPanel(p);
                    }
                }
                //Color color = colorChooser.showDialog(colorMenu, "Change Color", currentSubTabContainerHandler.getColor());
                colorChooser.setColor(currentSubTabContainerHandler.getColor());
                JDialog dialog = JColorChooser.createDialog(
                        sharedParameters.get_mainFrame(),
                        "Choose a Color",
                        true,
                        colorChooser,
                        null,
                        null);
                dialog.setVisible(true);
                if (colorChooser.getColor() != null) {
                    currentSubTabContainerHandler.setColor(colorChooser.getColor(), true);
                    sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
                }
            });
            customStyleMenu.add(colorMenu);
            popupMenu.add(customStyleMenu);

            JMenuItem pasteStyleSearchTitleMenu = new JMenuItem("Find/Replace Style (Use RegEx in Title)");
            if (sharedParameters.copiedTabFeaturesObjectStyle == null) {
                pasteStyleSearchTitleMenu.setEnabled(false);
            }
            pasteStyleSearchTitleMenu.addActionListener(e -> {
                if (sharedParameters.copiedTabFeaturesObjectStyle != null) {
                    //currentSubTabContainerHandler.updateByTabFeaturesObjectStyle(sharedParameters.copiedTabFeaturesObjectStyle);
                    String titleKeyword = UIHelper.showPlainInputMessage("Enter a Regular Expression (case insensitive):", "Search in titles and replace their style", sharedParameters.searchedTabTitleForPasteStyle, sharedParameters.get_mainFrame());
                    if (!titleKeyword.isEmpty()) {
                        if (Utilities.isValidRegExPattern(titleKeyword)) {
                            sharedParameters.searchedTabTitleForPasteStyle = titleKeyword;
                            ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentSubTabContainerHandler.currentToolTab);
                            for (SubTabContainerHandler subTabContainerHandlerItem : subTabContainerHandlers) {
                                if(subTabContainerHandlerItem.getVisible()) {
                                    String subTabTitle = subTabContainerHandlerItem.getTabTitle();
                                    if (Pattern.compile(titleKeyword, Pattern.CASE_INSENSITIVE).matcher(subTabTitle).find()) {
                                        subTabContainerHandlerItem.updateByTabFeaturesObjectStyle(sharedParameters.copiedTabFeaturesObjectStyle, true);
                                    }
                                }
                            }
                            sharedParameters.allSettings.subTabSettings.saveSettings(currentSubTabContainerHandler.currentToolTab);
                            sharedParameters.printDebugMessage("Style pasted in titles which matched: " + titleKeyword);
                        } else {
                            UIHelper.showWarningMessage("Regular expression was invalid.", sharedParameters.get_mainFrame());
                            sharedParameters.printlnError("invalid regex: " + titleKeyword);
                        }
                    }

                }
            });
            popupMenu.add(pasteStyleSearchTitleMenu);

            popupMenu.addSeparator();
        }

        JMenu searchAndJumpMenu = new JMenu("Find Title (Use RegEx)");

        JMenuItem searchAndJumpDefineRegExMenu = new JMenuItem("Search by RegEx (case insensitive) [Ctrl+Shift+F]");

        searchAndJumpDefineRegExMenu.addActionListener(e -> {
            defineRegExPopupForSearchAndJump(sharedParameters, currentSubTabContainerHandler);
        });
        searchAndJumpMenu.add(searchAndJumpDefineRegExMenu);

        JMenuItem jumpToNextTabByTitleMenu = new JMenuItem("Next"+ " [F3]");
        if (sharedParameters.searchedTabTitleForJumpToTab.isEmpty()) {
            jumpToNextTabByTitleMenu.setEnabled(false);
        } else {
            jumpToNextTabByTitleMenu.setToolTipText("Search for: " + sharedParameters.searchedTabTitleForJumpToTab);
        }

        jumpToNextTabByTitleMenu.addActionListener(e -> {
            searchInTabTitlesAndJump(sharedParameters,currentSubTabContainerHandler, notificationMenuItem, true);
        });
        searchAndJumpMenu.add(jumpToNextTabByTitleMenu);

        JMenuItem jumpToPreviousTabByTitleMenu = new JMenuItem("Previous"+ " [Shift+F3]");
        if (sharedParameters.searchedTabTitleForJumpToTab.isEmpty()) {
            jumpToPreviousTabByTitleMenu.setEnabled(false);
        } else {
            jumpToPreviousTabByTitleMenu.setToolTipText("Search for: " + sharedParameters.searchedTabTitleForJumpToTab);
        }

        jumpToPreviousTabByTitleMenu.addActionListener(e -> {
            searchInTabTitlesAndJump(sharedParameters, currentSubTabContainerHandler, notificationMenuItem, false);
        });

        searchAndJumpMenu.add(jumpToPreviousTabByTitleMenu);

        if (sharedParameters.searchedTabTitleForJumpToTab.isEmpty()) {
            searchAndJumpMenu.setText("Find Title (Click > Use RegEx)");

            searchAndJumpMenu.addMouseListener(new MouseAdapterExtensionHandler(mouseEvent -> {
                if(SwingUtilities.isLeftMouseButton(mouseEvent)){
                    searchAndJumpDefineRegExMenu.doClick();
                    popupMenu.setVisible(false);

                }
            }, MouseEvent.MOUSE_CLICKED));
        } else {
            // we want to rename searchAndJumpMenu so it shows what would happen when it is clicked!
            searchAndJumpMenu.setText("Find Title (Click > Next, Right-Click > Prev)");

            searchAndJumpMenu.addMouseListener(new MouseAdapterExtensionHandler(mouseEvent -> {
                if(SwingUtilities.isRightMouseButton(mouseEvent)){
                    jumpToPreviousTabByTitleMenu.doClick();
                }else{
                    jumpToNextTabByTitleMenu.doClick();
                }
            }, MouseEvent.MOUSE_CLICKED));
        }

        popupMenu.add(searchAndJumpMenu);

        JMenu filterTitleMenu = new JMenu("Filter Titles (Click > Use RegEx)");

        JMenuItem removeFilterTitle = new JMenuItem("Show All");
        if(!sharedParameters.isFiltered(currentSubTabContainerHandler.currentToolTab)){
            removeFilterTitle.setEnabled(false);
        }
        removeFilterTitle.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showAllTabTitles(sharedParameters, currentSubTabContainerHandler);
            }
        });
        filterTitleMenu.add(removeFilterTitle);

        JMenuItem toggleCurrentTabVisibilityFilterTitle = new JMenuItem("Toggle Current Tab Visibility");
        toggleCurrentTabVisibilityFilterTitle.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                toggleCurrentTabVisibility(sharedParameters, currentSubTabContainerHandler);
            }
        });
        filterTitleMenu.add(toggleCurrentTabVisibilityFilterTitle);

        filterTitleMenu.addSeparator();

        JMenuItem defineFilterTitleRegEx = new JMenuItem("Define RegEx (case insensitive)");
        defineFilterTitleRegEx.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String titleKeyword = UIHelper.showPlainInputMessage("Enter a Regular Expression:", "Filter Titles", sharedParameters.titleFilterRegEx, sharedParameters.get_mainFrame());
                if (!titleKeyword.isEmpty()) {
                    if (Utilities.isValidRegExPattern(titleKeyword)) {
                        showAllTabTitles(sharedParameters, currentSubTabContainerHandler);
                        sharedParameters.titleFilterRegEx = titleKeyword;
                        sharedParameters.filterOperationMode.put(currentSubTabContainerHandler.currentToolTab, 0);
                        setTabTitleFilter(sharedParameters, currentSubTabContainerHandler);
                    } else {
                        UIHelper.showWarningMessage("Regular expression was invalid.", sharedParameters.get_mainFrame());
                        sharedParameters.printlnError("invalid regex: " + titleKeyword);
                    }
                }

            }
        });
        filterTitleMenu.add(defineFilterTitleRegEx);

        JMenuItem numericalFilterTitle = new JMenuItem("Numerical Titles");
        numericalFilterTitle.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showAllTabTitles(sharedParameters, currentSubTabContainerHandler);
                sharedParameters.titleFilterRegEx = "^\\s*\\d+\\s*(\\(#\\d+\\)\\s*)?$";
                sharedParameters.filterOperationMode.put(currentSubTabContainerHandler.currentToolTab, 0);
                setTabTitleFilter(sharedParameters, currentSubTabContainerHandler);
            }
        });
        filterTitleMenu.add(numericalFilterTitle);

        JMenuItem customStylesFilterTitle = new JMenuItem("Custom Styles");
        customStylesFilterTitle.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showAllTabTitles(sharedParameters, currentSubTabContainerHandler);
                sharedParameters.titleFilterRegEx = "";
                sharedParameters.filterOperationMode.put(currentSubTabContainerHandler.currentToolTab, 1);
                setTabTitleFilter(sharedParameters, currentSubTabContainerHandler);
            }
        });
        filterTitleMenu.add(customStylesFilterTitle);

        JMenuItem customStylesOrCustomNamesFilterTitle = new JMenuItem("Custom Styles or Not Numerical Titles");
        customStylesOrCustomNamesFilterTitle.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                showAllTabTitles(sharedParameters, currentSubTabContainerHandler);
                sharedParameters.titleFilterRegEx = "^\\s*\\d+\\s*(\\(#\\d+\\)\\s*)?$";
                sharedParameters.filterOperationMode.put(currentSubTabContainerHandler.currentToolTab, 2);
                setTabTitleFilter(sharedParameters, currentSubTabContainerHandler);
            }
        });
        filterTitleMenu.add(customStylesOrCustomNamesFilterTitle);
        filterTitleMenu.addSeparator();


        JCheckBoxMenuItem filterTitleMenuNegativeSearch = new JCheckBoxMenuItem("Use Negative Logic");
        filterTitleMenuNegativeSearch.setState(sharedParameters.isTitleFilterNegative);

        filterTitleMenuNegativeSearch.addActionListener(e -> {
            sharedParameters.isTitleFilterNegative = !sharedParameters.isTitleFilterNegative;
            if(sharedParameters.isFiltered(currentSubTabContainerHandler.currentToolTab)){
                showAllTabTitles(sharedParameters, currentSubTabContainerHandler);
                setTabTitleFilter(sharedParameters, currentSubTabContainerHandler);
            }
        });

        filterTitleMenu.add(filterTitleMenuNegativeSearch);

        if(sharedParameters.isFiltered(currentSubTabContainerHandler.currentToolTab)){
            filterTitleMenu.setText("Filter Titles (Click > Use RegEx, Right-Click > Show All)");
            filterTitleMenu.addMouseListener(new MouseAdapterExtensionHandler(mouseEvent -> {
                if(SwingUtilities.isRightMouseButton(mouseEvent)){
                    removeFilterTitle.doClick();
                    popupMenu.setVisible(false);
                }else{
                    defineFilterTitleRegEx.doClick();
                    popupMenu.setVisible(false);
                }
            }, MouseEvent.MOUSE_CLICKED));
        }else{
            filterTitleMenu.addMouseListener(new MouseAdapterExtensionHandler(mouseEvent -> {
                if(!SwingUtilities.isRightMouseButton(mouseEvent)){
                    defineFilterTitleRegEx.doClick();
                    popupMenu.setVisible(false);
                }
            }, MouseEvent.MOUSE_CLICKED));
        }



        popupMenu.add(filterTitleMenu);

        JMenuItem copyTitleMenu = new JMenuItem("Copy Title");
        copyTitleMenu.addActionListener(e -> {
            String tabTitle = currentSubTabContainerHandler.getTabTitle();
            // copying to clipboard as well
            Toolkit.getDefaultToolkit()
                    .getSystemClipboard()
                    .setContents(
                            new StringSelection(tabTitle),
                            null
                    );
            sharedParameters.printDebugMessage("Title copied...");
        });
        popupMenu.add(copyTitleMenu);

        JMenuItem pasteTitleMenu = new JMenuItem("Paste Title");

        try{
            String clipboardText = (String) Toolkit.getDefaultToolkit()
                    .getSystemClipboard().getData(DataFlavor.stringFlavor);
            sharedParameters.lastClipboardText = clipboardText.trim().replaceAll("(?<=[^\\s])\\s+\\(#\\d+\\)\\s*$", "");
        }catch(Exception e){
            sharedParameters.lastClipboardText = "";
        }


        if (sharedParameters.lastClipboardText.isBlank()) {
            pasteTitleMenu.setEnabled(false);
        } else {
            pasteTitleMenu.setToolTipText("Clipboard value: " + StringUtils.abbreviate(sharedParameters.lastClipboardText, 100));
        }

        pasteTitleMenu.addActionListener(e -> {
            if (!sharedParameters.lastClipboardText.isBlank()) {
                currentSubTabContainerHandler.setTabTitle(sharedParameters.lastClipboardText, true);
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
                sharedParameters.printDebugMessage("Title pasted...");
            }
        });
        popupMenu.add(pasteTitleMenu);

        JMenuItem renameTitleMenu = new JMenuItem("Rename Title");
        renameTitleMenu.addActionListener(e -> {
            String newTitle = UIHelper.showPlainInputMessage("Edit the Title", "Rename Title", currentSubTabContainerHandler.getTabTitle(), sharedParameters.get_mainFrame());
            if (!newTitle.isEmpty() && !newTitle.equals(currentSubTabContainerHandler.getTabTitle())) {
                currentSubTabContainerHandler.setTabTitle(newTitle, true);
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
                sharedParameters.printDebugMessage("Title renamed...");
            }
        });
        popupMenu.add(renameTitleMenu);


        JMenuItem matchReplaceTitleMenu = new JMenuItem("Match/Replace Titles (Use RegEx)");
        matchReplaceTitleMenu.addActionListener(e -> {
            //currentSubTabContainerHandler.updateByTabFeaturesObjectStyle(sharedParameters.copiedTabFeaturesObjectStyle);
            String[] matchReplaceResult = UIHelper.showPlainInputMessages(new String[]{"Find what (start it with `(?i)` for case insensitive RegEx):","Replace with:"}, "Title Match and Replace (RegEx)", new String[]{sharedParameters.matchReplaceTitle_RegEx,sharedParameters.matchReplaceTitle_ReplaceWith}, sharedParameters.get_mainFrame());
            sharedParameters.matchReplaceTitle_RegEx = matchReplaceResult[0];
            sharedParameters.matchReplaceTitle_ReplaceWith = matchReplaceResult[1];
            if (!sharedParameters.matchReplaceTitle_RegEx.isEmpty()) {
                if (Utilities.isValidRegExPattern(sharedParameters.matchReplaceTitle_RegEx)) {
                    ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentSubTabContainerHandler.currentToolTab);
                    for (SubTabContainerHandler subTabContainerHandlerItem : subTabContainerHandlers) {
                        if(subTabContainerHandlerItem.getVisible()) {
                            String subTabTitle = subTabContainerHandlerItem.getTabTitle();
                            if (Pattern.compile(sharedParameters.matchReplaceTitle_RegEx).matcher(subTabTitle).find()) {
                                subTabContainerHandlerItem.setTabTitle(subTabContainerHandlerItem.getTabTitle().replaceAll(sharedParameters.matchReplaceTitle_RegEx, sharedParameters.matchReplaceTitle_ReplaceWith), true);
                            }
                        }
                    }
                    sharedParameters.allSettings.subTabSettings.saveSettings(currentSubTabContainerHandler.currentToolTab);
                    sharedParameters.printDebugMessage("Match and replace titles finished. -RegEx: " + sharedParameters.matchReplaceTitle_RegEx + " -Replace with: "+sharedParameters.matchReplaceTitle_ReplaceWith);
                } else {
                    UIHelper.showWarningMessage("Regular expression was invalid.", sharedParameters.get_mainFrame());
                    sharedParameters.printlnError("invalid regex: " + sharedParameters.matchReplaceTitle_RegEx);
                }
            }
        });
        popupMenu.add(matchReplaceTitleMenu);

        JMenu previousTitlesMenu = new JMenu("Previous Titles");

        JMenu previousTitlesMenuSet = new JMenu("Set");
        JMenu previousTitlesMenuCopy = new JMenu("Copy");
        JMenuItem previousTitlesMenuClearHistory = new JMenuItem("Clear History");

        if(currentSubTabContainerHandler.getTitleHistory().length <= 1){
            previousTitlesMenu.setEnabled(false);
            previousTitlesMenuSet.setEnabled(false);
            previousTitlesMenuCopy.setEnabled(false);
            previousTitlesMenuClearHistory.setEnabled(false);
        }else{
            String[] uniqueInvertedTitleHistoryArray = currentSubTabContainerHandler.getTitleHistory();

            for (String tempPrevTitle : uniqueInvertedTitleHistoryArray) {
                if (!tempPrevTitle.equalsIgnoreCase(currentSubTabContainerHandler.getTabTitle())) {
                    JMenuItem previousTitleMenuSet = new JMenuItem(new AbstractAction(tempPrevTitle) {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            currentSubTabContainerHandler.setTabTitle(tempPrevTitle, true);
                            sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
                            sharedParameters.printDebugMessage("Previous title has been set.");
                        }
                    });
                    previousTitlesMenuSet.add(previousTitleMenuSet);

                    JMenuItem previousTitleMenuCopy = new JMenuItem(new AbstractAction(tempPrevTitle) {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            Toolkit.getDefaultToolkit()
                                    .getSystemClipboard()
                                    .setContents(
                                            new StringSelection(tempPrevTitle),
                                            null
                                    );
                            sharedParameters.printDebugMessage("A previous title has been copied.");
                        }
                    });
                    previousTitlesMenuCopy.add(previousTitleMenuCopy);
                }
            }

            previousTitlesMenuClearHistory.addActionListener(new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    currentSubTabContainerHandler.setTitleHistory(null);
                    sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
                    sharedParameters.printDebugMessage("Previous titles have been cleared.");
                }
            });
        }
        previousTitlesMenu.add(previousTitlesMenuSet);
        previousTitlesMenu.add(previousTitlesMenuCopy);
        previousTitlesMenu.add(previousTitlesMenuClearHistory);


        popupMenu.add(previousTitlesMenu);


        popupMenu.addSeparator();

        JMenu jumpMenu = new JMenu("Jump To (Click > Next, Right-Click > Prev)");
        JMenuItem jumpToFirstTabMenu = new JMenuItem("First Tab [Home]");

        jumpToFirstTabMenu.addActionListener(e -> {
            jumpToFirstTab(sharedParameters, currentSubTabContainerHandler);
        });


        jumpMenu.add(jumpToFirstTabMenu);

        JMenuItem jumpToLastTabMenu = new JMenuItem("Last Tab [End]");

        jumpToLastTabMenu.addActionListener(e -> {
            jumpToLastTab(sharedParameters, currentSubTabContainerHandler);
        });

        jumpMenu.add(jumpToLastTabMenu);

        JMenuItem jumpToPreviousTabMenu = new JMenuItem("Previous Tab [Left Arrow]");

        jumpToPreviousTabMenu.addActionListener(e -> {
            jumpToPreviousTab(sharedParameters, currentSubTabContainerHandler, notificationMenuItem);
        });

        jumpMenu.add(jumpToPreviousTabMenu);

        JMenuItem jumpToNextTabMenu = new JMenuItem("Next Tab [Right Arrow]");
        jumpToNextTabMenu.addActionListener(e -> {
            jumpToNextTab(sharedParameters, currentSubTabContainerHandler, notificationMenuItem);
        });
        jumpMenu.add(jumpToNextTabMenu);

        JMenuItem jumpToPreviouslySelectedTabMenu = new JMenuItem("Back [Alt+Left Arrow]");
        if(sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabContainerHandler.currentToolTab).size() <= 0)
            jumpToPreviouslySelectedTabMenu.setEnabled(false);
        jumpToPreviouslySelectedTabMenu.addActionListener(e -> {
            jumpToPreviosulySelectedTab(sharedParameters, currentSubTabContainerHandler, notificationMenuItem);
        });
        jumpMenu.add(jumpToPreviouslySelectedTabMenu);

        JMenuItem jumpToNextlySelectedTabMenu = new JMenuItem("Forward [Alt+Right Arrow]");
        if(sharedParameters.subTabNextlySelectedIndexHistory.get(currentSubTabContainerHandler.currentToolTab).size() <= 0)
            jumpToNextlySelectedTabMenu.setEnabled(false);
        jumpToNextlySelectedTabMenu.addActionListener(e -> {
            jumpToNextlySelectedTab(sharedParameters, currentSubTabContainerHandler, notificationMenuItem);
        });
        jumpMenu.add(jumpToNextlySelectedTabMenu);




        jumpMenu.addMouseListener(new MouseAdapterExtensionHandler(mouseEvent -> {
            if(SwingUtilities.isRightMouseButton(mouseEvent)){
                jumpToPreviousTabMenu.doClick();
            }else{
                jumpToNextTabMenu.doClick();
            }
        }, MouseEvent.MOUSE_CLICKED));

        popupMenu.add(jumpMenu);
/*
        JMenu closingTabsMenu = new JMenu("Closing tab options");
        JMenuItem showOriginalTabCloseMenuMenu = new JMenuItem("Show original Burp Suite tab closing options");

        showOriginalTabCloseMenuMenu.addActionListener(e -> {

            Container currentTabContainer = currentSubTabContainerHandler.currentTab;
            Component firstTabComponent = currentTabContainer.getComponents()[0];
            MouseEvent me = new MouseEvent(currentTabContainer.getParent().getParent(), 0, 0, MouseEvent.BUTTON3, currentSubTabContainerHandler.currentTab.getLocationOnScreen().x, currentSubTabContainerHandler.currentTab.getLocationOnScreen().y, 1, true);

            for(MouseListener ml: firstTabComponent.getMouseListeners()){
                ml.mouseClicked(me);
            }

        });
        closingTabsMenu.add(showOriginalTabCloseMenuMenu);

        popupMenu.add(closingTabsMenu);
*/

        JMenu tabScreenshotMenu = new JMenu("Capture Screenshot");
        JMenuItem saveScreenshotToClipboardMenu = new JMenuItem("Clipboard");
        saveScreenshotToClipboardMenu.addActionListener(e -> {

            Rectangle componentRect = currentSubTabContainerHandler.parentTabbedPane.getSelectedComponent().getBounds();
            BufferedImage bufferedImage = new BufferedImage(componentRect.width, componentRect.height, BufferedImage.TYPE_INT_RGB);
            currentSubTabContainerHandler.parentTabbedPane.getSelectedComponent().paint(bufferedImage.getGraphics());
            ImageHelper.setClipboard(bufferedImage);
        });
        tabScreenshotMenu.add(saveScreenshotToClipboardMenu);

        JMenuItem saveScreenshotToFileMenu = new JMenuItem("File");
        saveScreenshotToFileMenu.addActionListener(e -> {
            Rectangle componentRect = currentSubTabContainerHandler.parentTabbedPane.getSelectedComponent().getBounds();
            BufferedImage bufferedImage = new BufferedImage(componentRect.width, componentRect.height, BufferedImage.TYPE_INT_ARGB);
            currentSubTabContainerHandler.parentTabbedPane.getSelectedComponent().paint(bufferedImage.getGraphics());

            String saveLocation = UIHelper.showDirectorySaveDialog(sharedParameters.allSettings.subTabSettings.lastSavedImageLocation, sharedParameters.get_mainFrame());

            if(!saveLocation.isEmpty()){
                sharedParameters.allSettings.subTabSettings.lastSavedImageLocation = saveLocation;
                String strDate = new SimpleDateFormat("yyyyMMddHHmmss").format(new Date());
                String imageFileLocation = saveLocation + "/" + currentSubTabContainerHandler.getTabTitle().replaceAll("[^a-zA-Z0-9-_.]", "_") + "_" + strDate + ".png";

                try{
                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    ImageIO.write(bufferedImage, "png", os);
                    try(OutputStream outputStream = new FileOutputStream(imageFileLocation)) {
                        os.writeTo(outputStream);
                    }
                }catch(Exception err){
                    sharedParameters.printlnError("Image file could not be saved: " + imageFileLocation);
                    sharedParameters.printDebugMessage(err.getMessage());
                }

                File imageFile = new File(imageFileLocation);
                if(imageFile.exists()){
                    sharedParameters.printlnOutput("Image file saved successfully: " + imageFileLocation);
                }else{
                    sharedParameters.printlnError("Image file could not be saved: " + imageFileLocation);
                    UIHelper.showWarningMessage("Image file could not be saved: " + imageFileLocation, sharedParameters.get_mainFrame());
                }

            }
        });
        tabScreenshotMenu.add(saveScreenshotToFileMenu);
        popupMenu.add(tabScreenshotMenu);

        JMenuItem jumpToAddTabMenu = new JMenuItem("Add an Empty New Tab");

        jumpToAddTabMenu.addActionListener(actionEvent -> {

            Container dotdotdotTabContainer = (Container) currentSubTabContainerHandler.parentTabbedPane.getTabComponentAt(currentSubTabContainerHandler.parentTabbedPane.getTabCount() - 1);

            // this is a hack to get the Y location of the ... tab!
            int x = dotdotdotTabContainer.getLocationOnScreen().x + dotdotdotTabContainer.getWidth()/2;
            int burp_x = dotdotdotTabContainer.getParent().getLocationOnScreen().x + dotdotdotTabContainer.getParent().getWidth() - dotdotdotTabContainer.getWidth()/2;
            if(x > burp_x){
                x = burp_x;
            }

            int y = dotdotdotTabContainer.getLocationOnScreen().y + dotdotdotTabContainer.getHeight()/2;
            int burp_y = dotdotdotTabContainer.getParent().getLocationOnScreen().y + dotdotdotTabContainer.getParent().getHeight() - dotdotdotTabContainer.getHeight()/2;
            if(y > burp_y || y < burp_y - dotdotdotTabContainer.getHeight()){
                y = burp_y;
            }

            try{
                Robot robot = new Robot();
                robot.mouseMove(x, y);
            }catch (Exception errRobot){
                sharedParameters.printlnError("Could not change mouse location: " + errRobot.getMessage());
            }

            jumpToPreviosulySelectedTab(sharedParameters, currentSubTabContainerHandler, notificationMenuItem);

            jumpToTabIndex(sharedParameters,currentSubTabContainerHandler,currentSubTabContainerHandler.parentTabbedPane.getTabCount() - 1);
        });

        popupMenu.add(jumpToAddTabMenu);

        popupMenu.addSeparator();

        BurpUITools.MainTabs tool = currentSubTabContainerHandler.currentToolTab;

        if(sharedParameters.subTabSupportedTabs.contains(tool)) {
            JCheckBoxMenuItem toolSubTabPaneScrollableLayout = new JCheckBoxMenuItem("Scrollable " + tool + " Tabs");
            if ((boolean) sharedParameters.preferences.getSetting("isScrollable_" + tool)) {
                toolSubTabPaneScrollableLayout.setSelected(true);
            }

            toolSubTabPaneScrollableLayout.addActionListener((e) -> {
                if ((boolean) sharedParameters.preferences.getSetting("isScrollable_" + tool)) {
                    SwingUtilities.invokeLater(new Runnable() {
                        @Override
                        public void run() {
                            new Thread(() -> {
                                currentSubTabContainerHandler.parentTabbedPane.setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT);
                            }).start();
                        }
                    });
                    sharedParameters.allSettings.saveSettings("isScrollable_" + tool, false);
                } else {
                    SwingUtilities.invokeLater(new Runnable() {
                        @Override
                        public void run() {
                            new Thread(() -> {
                                currentSubTabContainerHandler.parentTabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
                                new java.util.Timer().schedule(
                                        new java.util.TimerTask() {
                                            @Override
                                            public void run() {
                                                jumpToTabIndex(sharedParameters,currentSubTabContainerHandler,0);
                                                jumpToTabIndex(sharedParameters,currentSubTabContainerHandler,currentSubTabContainerHandler.getTabIndex());
                                            }
                                        },
                                        1000
                                );
                            }).start();
                        }
                    });
                    sharedParameters.allSettings.saveSettings("isScrollable_" + tool, true);
                }
            });

            popupMenu.add(toolSubTabPaneScrollableLayout);



            JCheckBoxMenuItem toolSubTabPaneTabFixedPositionLayout = new JCheckBoxMenuItem("Fixed Tab Position for " + tool);
            if ((boolean) sharedParameters.preferences.getSetting("isTabFixedPosition_" + tool)) {
                toolSubTabPaneTabFixedPositionLayout.setSelected(true);
            }

            toolSubTabPaneTabFixedPositionLayout.addActionListener((e) -> {
                if ((boolean) sharedParameters.preferences.getSetting("isTabFixedPosition_" + tool)) {
                    changeToolTabbedPaneUI(sharedParameters, currentSubTabContainerHandler, false);
                    sharedParameters.allSettings.saveSettings("isTabFixedPosition_" + tool, false);
                } else {
                    changeToolTabbedPaneUI(sharedParameters, currentSubTabContainerHandler, false);
                    sharedParameters.allSettings.saveSettings("isTabFixedPosition_" + tool, true);
                }
            });

            popupMenu.add(toolSubTabPaneTabFixedPositionLayout);

            JCheckBoxMenuItem toolSubTabPaneMouseWheelScroll = new JCheckBoxMenuItem("Activate Mouse Wheel: MW > Scroll, MW+Ctrl > Resize");
            if ((boolean) sharedParameters.preferences.getSetting("mouseWheelToScroll_" + tool)) {
                toolSubTabPaneMouseWheelScroll.setSelected(true);
            }

            toolSubTabPaneMouseWheelScroll.addActionListener((e) -> {
                if ((boolean) sharedParameters.preferences.getSetting("mouseWheelToScroll_" + tool)) {
                    SubTabActions.removeMouseWheelFromJTabbedPane(sharedParameters, tool, true);
                    sharedParameters.allSettings.saveSettings("mouseWheelToScroll_" + tool, false);
                } else {
                    SubTabActions.addMouseWheelToJTabbedPane(sharedParameters, tool, false);
                    sharedParameters.allSettings.saveSettings("mouseWheelToScroll_" + tool, true);
                }
            });

            popupMenu.add(toolSubTabPaneMouseWheelScroll);
        }

        return popupMenu;
    }

    private static void changeToolTabbedPaneUI(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler, boolean shouldOriginalBeSet) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new Thread(() -> {
                    // should have already been loaded but just in case something has changed
                    // hopefully it has not been tainted already!
                    if(sharedParameters.originalSubTabbedPaneUI.get(currentSubTabContainerHandler.currentToolTab) == null &&
                            sharedParameters.get_toolTabbedPane(currentSubTabContainerHandler.currentToolTab) != null){
                        sharedParameters.originalSubTabbedPaneUI.put(currentSubTabContainerHandler.currentToolTab,
                                sharedParameters.get_toolTabbedPane(currentSubTabContainerHandler.currentToolTab).getUI());
                    }


                    boolean isFixedTabPosition = ((boolean) sharedParameters.preferences.getSetting("isTabFixedPosition_" + currentSubTabContainerHandler.currentToolTab));
                    boolean isFiltered = sharedParameters.isFiltered(currentSubTabContainerHandler.currentToolTab);

                    if(shouldOriginalBeSet || (!isFixedTabPosition && !isFiltered)){
                        /* // replaced by updateUI()
                        // just in case any of these settings remain even after the original UI reload!
                        sharedParameters.get_toolTabbedPane(currentSubTabContainerHandler.currentToolTab).setUI(new FlatTabbedPaneUI(){
                            @Override
                            protected int calculateTabWidth(int tabPlacement, int tabIndex, FontMetrics metrics) {
                                return super.calculateTabWidth(tabPlacement, tabIndex, metrics);
                            }
                            @Override
                            protected boolean shouldRotateTabRuns(int i) {
                                return true;
                            }
                        });
                        sharedParameters.get_toolTabbedPane(currentSubTabContainerHandler.currentToolTab).setUI(sharedParameters.originalSubTabbedPaneUI.get(currentSubTabContainerHandler.currentToolTab));
                        */
                        sharedParameters.get_toolTabbedPane(currentSubTabContainerHandler.currentToolTab).updateUI();
                    }else{
                        if(isFixedTabPosition && isFiltered){
                            sharedParameters.get_toolTabbedPane(currentSubTabContainerHandler.currentToolTab).setUI(new FlatTabbedPaneUI(){
                                @Override
                                protected int calculateTabWidth(int tabPlacement, int tabIndex, FontMetrics metrics) {
                                    if(sharedParameters.allSubTabContainerHandlers.get(currentSubTabContainerHandler.currentToolTab).stream()
                                            .filter(s -> !s.getVisible() && s.getTabIndex()==tabIndex).toArray().length > 0){
                                        return 0;
                                    }
                                    return super.calculateTabWidth(tabPlacement, tabIndex, metrics);
                                }
                                @Override
                                protected boolean shouldRotateTabRuns(int i) {
                                    return false;
                                }
                            });
                        }else if(isFixedTabPosition){
                            sharedParameters.get_toolTabbedPane(currentSubTabContainerHandler.currentToolTab).setUI(new FlatTabbedPaneUI(){
                                @Override
                                protected boolean shouldRotateTabRuns(int i) {
                                    return false;
                                }
                            });
                        }else{
                            sharedParameters.get_toolTabbedPane(currentSubTabContainerHandler.currentToolTab).setUI(new FlatTabbedPaneUI(){
                                @Override
                                protected int calculateTabWidth(int tabPlacement, int tabIndex, FontMetrics metrics) {
                                    if(sharedParameters.allSubTabContainerHandlers.get(currentSubTabContainerHandler.currentToolTab).stream()
                                            .filter(s -> !s.getVisible() && s.getTabIndex()==tabIndex).toArray().length > 0){
                                        return 0;
                                    }
                                    return super.calculateTabWidth(tabPlacement, tabIndex, metrics);
                                }
                            });
                        }
                    }

                    sharedParameters.get_toolTabbedPane(currentSubTabContainerHandler.currentToolTab).revalidate();
                    sharedParameters.get_toolTabbedPane(currentSubTabContainerHandler.currentToolTab).repaint();
                    new java.util.Timer().schedule(
                            new java.util.TimerTask() {
                                @Override
                                public void run() {
                                    sharedParameters.allSettings.subTabSettings.updateSubTabsUI(currentSubTabContainerHandler.currentToolTab);
                                }
                            },
                            3000 // 3 seconds-delay to ensure all has been settled!
                    );
                }).start();
            }
        });
    }

    public static void setTabTitleFilter(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler) {
        // filterOperationMode -->
        //operationMode=0 -> use RegEx
        //operationMode=1 -> Custom style only
        //operationMode=2 -> Custom style or not numerical
        if(!sharedParameters.titleFilterRegEx.isBlank() || sharedParameters.filterOperationMode.get(currentSubTabContainerHandler.currentToolTab) > 0){
            for (SubTabContainerHandler subTabContainerHandlerItem : sharedParameters.allSubTabContainerHandlers.get(currentSubTabContainerHandler.currentToolTab)) {
                String subTabTitle = subTabContainerHandlerItem.getTabTitle();

                // if it is not negative (default), then if we have a match, we have a winner so default is false and vice versa
                // the exception is for mode 2, as if we have a match for numbers then we don't like it!
                boolean interestingItemUsingRegEx = sharedParameters.isTitleFilterNegative;

                if(!sharedParameters.titleFilterRegEx.isBlank()){
                    // RegEx Matched
                    interestingItemUsingRegEx = Pattern.compile(sharedParameters.titleFilterRegEx, Pattern.CASE_INSENSITIVE).matcher(subTabTitle).find();
                }

                if(sharedParameters.filterOperationMode.get(currentSubTabContainerHandler.currentToolTab) == 2){
                    //  in Custom style or not numerical, we need to exclude all numbers as RegEx has been set to numbers only, we need to make it negative again!
                    interestingItemUsingRegEx = !interestingItemUsingRegEx;
                }

                if(sharedParameters.isTitleFilterNegative){
                    // in negative state, anything positive will be negative at this point!
                    interestingItemUsingRegEx = !interestingItemUsingRegEx;
                }

                boolean interestingItemUsingStyle = sharedParameters.isTitleFilterNegative;
                if((sharedParameters.filterOperationMode.get(currentSubTabContainerHandler.currentToolTab) > 0)){
                    // Checking Custom style only when we do not think it is an interesting item by this point
                    interestingItemUsingStyle = !subTabContainerHandlerItem.isDefault();

                    if(sharedParameters.isTitleFilterNegative){
                        // in negative state, anything positive will be negative at this point!
                        interestingItemUsingStyle = !interestingItemUsingStyle;
                    }
                }

                boolean isItFinallyInteresting;
                if(sharedParameters.filterOperationMode.get(currentSubTabContainerHandler.currentToolTab) == 2){
                    // mode 2
                    isItFinallyInteresting = interestingItemUsingStyle || interestingItemUsingRegEx;
                }else if(sharedParameters.filterOperationMode.get(currentSubTabContainerHandler.currentToolTab) == 1){
                    // mode 1
                    isItFinallyInteresting = interestingItemUsingStyle;
                }else{
                    // mode 0
                    isItFinallyInteresting = interestingItemUsingRegEx;
                }

                // if it is not an interesting item, we need to hide it!
                subTabContainerHandlerItem.setVisible(isItFinallyInteresting);
            }

            // now we need to change the UI so it will return 0 for width of the filtered tabs
            changingTabbedPaneUiToHideTabs(sharedParameters, currentSubTabContainerHandler);
        }
    }

    private static void changingTabbedPaneUiToHideTabs(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler){
        if (sharedParameters.isFiltered(currentSubTabContainerHandler.currentToolTab)) {
            sharedParameters.printDebugMessage("Changing UI so it can hide tabs");
            if(sharedParameters.originalSubTabbedPaneUI.get(currentSubTabContainerHandler.currentToolTab) == null)
                sharedParameters.originalSubTabbedPaneUI.put(currentSubTabContainerHandler.currentToolTab,
                        sharedParameters.get_toolTabbedPane(currentSubTabContainerHandler.currentToolTab).getUI());

            changeToolTabbedPaneUI(sharedParameters, currentSubTabContainerHandler, false);
        } else {
            changeToolTabbedPaneUI(sharedParameters, currentSubTabContainerHandler, true);
            sharedParameters.printDebugMessage("There is no filter");
        }
    }

    public static void showAllTabTitles(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler) {
        if(sharedParameters.isFiltered(currentSubTabContainerHandler.currentToolTab)){
            for (SubTabContainerHandler subTabContainerHandlerItem : sharedParameters.allSubTabContainerHandlers.get(currentSubTabContainerHandler.currentToolTab)) {
                subTabContainerHandlerItem.setVisible(true);
            }
            changeToolTabbedPaneUI(sharedParameters, currentSubTabContainerHandler, true);
        }
    }

    public static void toggleCurrentTabVisibility(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler) {
        currentSubTabContainerHandler.setVisible(!currentSubTabContainerHandler.getVisible());

        sharedParameters.get_toolTabbedPane(currentSubTabContainerHandler.currentToolTab).revalidate();
        sharedParameters.get_toolTabbedPane(currentSubTabContainerHandler.currentToolTab).repaint();
        new java.util.Timer().schedule(
                new java.util.TimerTask() {
                    @Override
                    public void run() {
                        sharedParameters.allSettings.subTabSettings.updateSubTabsUI(currentSubTabContainerHandler.currentToolTab);
                    }
                },
                2000 // 2 seconds-delay to ensure all has been settled!
        );

        // now we need to change the UI so it will return 0 for width of the filtered tabs
        changingTabbedPaneUiToHideTabs(sharedParameters, currentSubTabContainerHandler);
    }

    public static SubTabContainerHandler getSubTabContainerHandlerFromEvent(SharpenerSharedParameters sharedParameters, AWTEvent event){
        SubTabContainerHandler subTabContainerHandler = null;
        if (event.getSource() instanceof JTabbedPane) {
            JTabbedPane tabbedPane = (JTabbedPane) event.getSource();

            // works with version 2022.1.1 - not tested in the previous versions!
            int currentSelection = tabbedPane.getSelectedIndex();

            subTabContainerHandler =  getSubTabContainerHandlerFromSharedParameters(sharedParameters, tabbedPane, currentSelection);
        }
        return subTabContainerHandler;
    }

    public static SubTabContainerHandler getSubTabContainerHandlerFromSharedParameters(SharpenerSharedParameters sharedParameters, JTabbedPane tabbedPane, int currentIndex){
        SubTabContainerHandler subTabContainerHandler = null;

        SubTabContainerHandler tempSubTabContainerHandler =  new SubTabContainerHandler(sharedParameters, tabbedPane, currentIndex, true);
        BurpUITools.MainTabs currentToolTab = tempSubTabContainerHandler.currentToolTab;

        ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentToolTab);

        if(subTabContainerHandlers!=null){
            int sharedParamIndex = subTabContainerHandlers.indexOf(tempSubTabContainerHandler);
            if(sharedParamIndex >=0 )
                subTabContainerHandler = subTabContainerHandlers.get(sharedParamIndex);
        }


        return subTabContainerHandler;
    }

    public static void showPopupMenu(SharpenerSharedParameters sharedParameters, AWTEvent event){
        showPopupMenu(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event), null);
    }

    public static void showPopupMenu(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler, AWTEvent event){
        // creating popup menu
        JPopupMenu popupMenu = createPopupMenu(sharedParameters, currentSubTabContainerHandler);
        //popupMenu.show(tabbedPane, event.getX(), event.getY());
        int x;
        int y;
        JTabbedPane tabbedPane = sharedParameters.get_toolTabbedPane(currentSubTabContainerHandler.currentToolTab);
        if (tabbedPane.getTabLayoutPolicy() == JTabbedPane.SCROLL_TAB_LAYOUT && event instanceof MouseEvent) {
            x = ((MouseEvent) event).getX();
            y = ((MouseEvent) event).getY() + tabbedPane.getTabComponentAt(currentSubTabContainerHandler.getTabIndex()).getHeight() / 2;
        } else {
            x = tabbedPane.getTabComponentAt(currentSubTabContainerHandler.getTabIndex()).getX();
            y = tabbedPane.getTabComponentAt(currentSubTabContainerHandler.getTabIndex()).getY() + tabbedPane.getTabComponentAt(currentSubTabContainerHandler.getTabIndex()).getHeight();
        }
        // showing popup menu
        popupMenu.show(tabbedPane, x, y);
    }

    public static void defineRegExPopupForSearchAndJump(SharpenerSharedParameters sharedParameters, AWTEvent event){
        defineRegExPopupForSearchAndJump(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event).currentToolTab);
    }

    public static void defineRegExPopupForSearchAndJump(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler){
        defineRegExPopupForSearchAndJump(sharedParameters, currentSubTabContainerHandler.currentToolTab);
    }

    public static void defineRegExPopupForSearchAndJump(SharpenerSharedParameters sharedParameters, BurpUITools.MainTabs currentToolTab){
        String titleKeyword = UIHelper.showPlainInputMessage("Enter a Regular Expression:", "Search in titles and jump to tab", sharedParameters.searchedTabTitleForJumpToTab, sharedParameters.get_mainFrame());
        if (!titleKeyword.isEmpty()) {
            boolean result = false;
            if (Utilities.isValidRegExPattern(titleKeyword)) {
                sharedParameters.searchedTabTitleForJumpToTab = titleKeyword;
                ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentToolTab);
                for (SubTabContainerHandler subTabContainerHandlerItem : subTabContainerHandlers) {
                    if(subTabContainerHandlerItem.getVisible()) {
                        String subTabTitle = subTabContainerHandlerItem.getTabTitle();
                        if (Pattern.compile(titleKeyword, Pattern.CASE_INSENSITIVE).matcher(subTabTitle).find()) {
                            jumpToTabIndex(sharedParameters, subTabContainerHandlerItem, subTabContainerHandlerItem.getTabIndex());
                            result = true;
                            break;
                        }
                    }
                }
                if (result) {
                    sharedParameters.printDebugMessage("Jumped to first title which matched: " + titleKeyword);
                } else {
                    sharedParameters.printDebugMessage("No title matched: " + titleKeyword);
                }

            } else {
                UIHelper.showWarningMessage("Regular expression was invalid.", sharedParameters.get_mainFrame());
                sharedParameters.printlnError("invalid regex: " + titleKeyword);
            }
        }
    }

    public static void searchInTabTitlesAndJump(SharpenerSharedParameters sharedParameters, AWTEvent event, Boolean isNext){
        searchInTabTitlesAndJump(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event), null, isNext);
    }

    public static void searchInTabTitlesAndJump(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler, JMenuItem notificationMenuItem, Boolean isNext){
        if (!sharedParameters.searchedTabTitleForJumpToTab.isEmpty() && currentSubTabContainerHandler!=null) {
            boolean result = false;
            ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentSubTabContainerHandler.currentToolTab);
            ArrayList<SubTabContainerHandler> tempSubTabContainerHandlers;
            if(isNext){
                tempSubTabContainerHandlers = new ArrayList<>(subTabContainerHandlers.subList(currentSubTabContainerHandler.parentTabbedPane.getSelectedIndex(),subTabContainerHandlers.size()));
            }else{
                tempSubTabContainerHandlers = new ArrayList<>(subTabContainerHandlers.subList(0,currentSubTabContainerHandler.parentTabbedPane.getSelectedIndex()));
                Collections.reverse(tempSubTabContainerHandlers);
            }

            for (SubTabContainerHandler subTabContainerHandlerItem : tempSubTabContainerHandlers) {
                if ((subTabContainerHandlerItem.getTabIndex() > subTabContainerHandlerItem.parentTabbedPane.getSelectedIndex() && isNext)
                        ||(subTabContainerHandlerItem.getTabIndex() < subTabContainerHandlerItem.parentTabbedPane.getSelectedIndex() && !isNext)) {
                    if(subTabContainerHandlerItem.getVisible()){
                        String subTabTitle = subTabContainerHandlerItem.getTabTitle();
                        if (Pattern.compile(sharedParameters.searchedTabTitleForJumpToTab, Pattern.CASE_INSENSITIVE).matcher(subTabTitle).find()) {
                            jumpToTabIndex(sharedParameters,subTabContainerHandlerItem,subTabContainerHandlerItem.getTabIndex());
                            // This is because when we use mouse action, the menu won't be closed
                            if(notificationMenuItem!=null)
                                setNotificationMenuMessage(sharedParameters,currentSubTabContainerHandler,notificationMenuItem,"Tab Title: " + currentSubTabContainerHandler.parentTabbedPane.getTitleAt(currentSubTabContainerHandler.parentTabbedPane.getSelectedIndex()));
                            result = true;
                            break;
                        }
                    }
                }
            }
            if (result) {
                sharedParameters.printDebugMessage("Matched title was found");
                sharedParameters.printDebugMessage("Jumped to a title which matched: " + sharedParameters.searchedTabTitleForJumpToTab);
            } else {
                sharedParameters.printDebugMessage("No new match was found");
            }
        }
    }

    public static void jumpToFirstTab(SharpenerSharedParameters sharedParameters, ActionEvent event) {
        jumpToFirstTab(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event));
    }

    public static void jumpToFirstTab(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler) {
        jumpToTabIndex(sharedParameters,currentSubTabContainerHandler,0);
        sharedParameters.printDebugMessage("Jump to first tab");
    }

    public static void jumpToLastTab(SharpenerSharedParameters sharedParameters, ActionEvent event) {
        jumpToLastTab(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event));
    }

    public static void jumpToLastTab(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler) {
        jumpToTabIndex(sharedParameters,currentSubTabContainerHandler,currentSubTabContainerHandler.parentTabbedPane.getTabCount() - 2);
        sharedParameters.printDebugMessage("Jump to last tab");
    }

    public static void jumpToPreviousTab(SharpenerSharedParameters sharedParameters, ActionEvent event) {
        jumpToPreviousTab(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event), null);
    }

    public static void jumpToPreviousTab(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler, JMenuItem notificationMenuItem) {
        if (currentSubTabContainerHandler.parentTabbedPane.getSelectedIndex() > 0) {
            int chosenOne = currentSubTabContainerHandler.parentTabbedPane.getSelectedIndex() -1;
            while(!currentSubTabContainerHandler.parentTabbedPane.isEnabledAt(chosenOne)){
                chosenOne--;
                if (chosenOne < 0 || chosenOne >= currentSubTabContainerHandler.parentTabbedPane.getTabCount()){
                    chosenOne = currentSubTabContainerHandler.parentTabbedPane.getSelectedIndex();
                    break;
                }
            }
            jumpToTabIndex(sharedParameters,currentSubTabContainerHandler,chosenOne);
            // This is because when we use mouse action, the menu won't be closed
            if(notificationMenuItem!=null)
                setNotificationMenuMessage(sharedParameters,currentSubTabContainerHandler,notificationMenuItem,"Tab Title: " + currentSubTabContainerHandler.parentTabbedPane.getTitleAt(currentSubTabContainerHandler.parentTabbedPane.getSelectedIndex()));

            sharedParameters.printDebugMessage("Jump to previous tab");
        }
    }

    public static void jumpToNextTab(SharpenerSharedParameters sharedParameters, ActionEvent event) {
        jumpToNextTab(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event), null);
    }

    public static void jumpToNextTab(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler, JMenuItem notificationMenuItem) {
        if (currentSubTabContainerHandler.parentTabbedPane.getSelectedIndex() < currentSubTabContainerHandler.parentTabbedPane.getTabCount() - 2) {
            int chosenOne = currentSubTabContainerHandler.parentTabbedPane.getSelectedIndex() + 1;
            while(!currentSubTabContainerHandler.parentTabbedPane.isEnabledAt(chosenOne)){
                chosenOne++;
                if (chosenOne < 0 || chosenOne >= currentSubTabContainerHandler.parentTabbedPane.getTabCount()){
                    chosenOne = currentSubTabContainerHandler.parentTabbedPane.getSelectedIndex();
                    break;
                }
            }

            jumpToTabIndex(sharedParameters,currentSubTabContainerHandler,chosenOne);
            // This is because when we use mouse action, the menu won't be closed
            if(notificationMenuItem != null)
                setNotificationMenuMessage(sharedParameters,currentSubTabContainerHandler,notificationMenuItem,"Tab Title: " + currentSubTabContainerHandler.parentTabbedPane.getTitleAt(currentSubTabContainerHandler.parentTabbedPane.getSelectedIndex()));

            sharedParameters.printDebugMessage("Jump to next tab");
        }
    }

    public static void jumpToPreviosulySelectedTab(SharpenerSharedParameters sharedParameters, ActionEvent event) {
        jumpToPreviosulySelectedTab(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event), null);
    }

    public static void jumpToPreviosulySelectedTab(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler, JMenuItem notificationMenuItem) {

        Integer previouslySelectedIndex = null;
        Integer currentSelectedIndex = sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabContainerHandler.currentToolTab).pollLast();

        if(!currentSubTabContainerHandler.isDotDotDotTab()){
            previouslySelectedIndex = sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabContainerHandler.currentToolTab).pollLast();
        }

        if(previouslySelectedIndex!=null && currentSubTabContainerHandler.parentTabbedPane.getTabComponentAt(previouslySelectedIndex) != null){
            jumpToTabIndex(sharedParameters,currentSubTabContainerHandler,previouslySelectedIndex, false, false);
            sharedParameters.printDebugMessage("Jump to previously selected tab");
        }else{
            sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabContainerHandler.currentToolTab).add(currentSelectedIndex);
            sharedParameters.printDebugMessage("No previously selected tab was found");
        }

        if (notificationMenuItem != null)
            setNotificationMenuMessage(sharedParameters, currentSubTabContainerHandler, notificationMenuItem, "Tab Title: " + currentSubTabContainerHandler.parentTabbedPane.getTitleAt(currentSubTabContainerHandler.parentTabbedPane.getSelectedIndex()));


    }

    public static void jumpToNextlySelectedTab(SharpenerSharedParameters sharedParameters, ActionEvent event) {
        jumpToNextlySelectedTab(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event), null);
    }

    public static void jumpToNextlySelectedTab(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler, JMenuItem notificationMenuItem) {
        Integer nextlySelectedIndex;
        nextlySelectedIndex = sharedParameters.subTabNextlySelectedIndexHistory.get(currentSubTabContainerHandler.currentToolTab).pollLast();

        if(nextlySelectedIndex!=null && currentSubTabContainerHandler.parentTabbedPane.getTabComponentAt(nextlySelectedIndex) != null){
            jumpToTabIndex(sharedParameters,currentSubTabContainerHandler,nextlySelectedIndex, false, true);
        }

        if (notificationMenuItem != null)
            setNotificationMenuMessage(sharedParameters, currentSubTabContainerHandler, notificationMenuItem, "Tab Title: " + currentSubTabContainerHandler.parentTabbedPane.getTitleAt(currentSubTabContainerHandler.parentTabbedPane.getSelectedIndex()));

        sharedParameters.printDebugMessage("Jump to previously selected tab");
    }

    public static void jumpToTabIndex(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler, int indexNumber) {
        jumpToTabIndex(sharedParameters, currentSubTabContainerHandler, indexNumber, true, true);
    }

    public static void jumpToTabIndex(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler, int indexNumber, boolean cleanNextlySelectedTabs, boolean ignoreNextlySelectedTabs){
        if(currentSubTabContainerHandler.parentTabbedPane.getTabComponentAt(indexNumber) != null){
            if(cleanNextlySelectedTabs){
                sharedParameters.subTabNextlySelectedIndexHistory.get(currentSubTabContainerHandler.currentToolTab).clear();
            }else{
                if(!ignoreNextlySelectedTabs &&
                        (sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabContainerHandler.currentToolTab).size() <= 0 ||
                                (sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabContainerHandler.currentToolTab).size() > 0 &&
                                        sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabContainerHandler.currentToolTab).getLast() != currentSubTabContainerHandler.getTabIndex()))
                ){
                    sharedParameters.subTabNextlySelectedIndexHistory.get(currentSubTabContainerHandler.currentToolTab).add(currentSubTabContainerHandler.getTabIndex());
                }

            }

            if((sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabContainerHandler.currentToolTab).size() <=0 ||
                    (sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabContainerHandler.currentToolTab).getLast() != indexNumber) &&
                            currentSubTabContainerHandler.parentTabbedPane.getTabCount()-1 != indexNumber)){
                sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabContainerHandler.currentToolTab).add(indexNumber);
            }
            currentSubTabContainerHandler.parentTabbedPane.setSelectedIndex(indexNumber);
        }
    }

}
