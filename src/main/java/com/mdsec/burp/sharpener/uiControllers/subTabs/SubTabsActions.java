// Burp Suite Extension Name: Sharpener
// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)
// Released initially as open source by MDSec - https://www.mdsec.co.uk
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener

package com.mdsec.burp.sharpener.uiControllers.subTabs;

import com.google.common.io.Files;
import com.irsdl.burp.generic.BurpUITools;
import com.mdsec.burp.sharpener.SharpenerSharedParameters;
import com.mdsec.burp.sharpener.objects.TabFeaturesObjectStyle;
import com.irsdl.generic.*;
import com.irsdl.generic.uiObjFinder.UiSpecObject;
import com.irsdl.generic.uiObjFinder.UIWalker;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.colorchooser.AbstractColorChooserPanel;
import java.awt.*;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.MouseEvent;
import java.awt.event.MouseWheelListener;
import java.awt.image.BufferedImage;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Objects;
import java.util.regex.Pattern;

public class SubTabsActions {
    public static void tabClicked(final MouseEvent event, SharpenerSharedParameters sharedParameters) {
        SubTabsContainerHandler subTabsContainerHandler = getSubTabContainerHandlerFromEvent(sharedParameters, event);

        if (subTabsContainerHandler == null) {
            sharedParameters.printlnError("Object has not been loaded yet, try in a few seconds or try to drag and drop the tab or add a new tab.");
        }

        if (subTabsContainerHandler == null || (!subTabsContainerHandler.isValid() && !subTabsContainerHandler.isDotDotDotTab()))
            return;

        subTabsContainerHandler.currentTabContainer.requestFocus();

        fixHistoryAndJumpToTabIndex(sharedParameters, subTabsContainerHandler, subTabsContainerHandler.getTabIndex(), true, true, false);

        if (SwingUtilities.isMiddleMouseButton(event) || event.isAltDown() || ((event.getModifiersEx() & ActionEvent.ALT_MASK) == ActionEvent.ALT_MASK)) {
            jumpToTabIndex(sharedParameters, subTabsContainerHandler, subTabsContainerHandler.getTabIndex());
            boolean isCTRL_Key = (event.getModifiersEx() & ActionEvent.CTRL_MASK) == ActionEvent.CTRL_MASK || event.isControlDown();
            // Middle key is like the Alt key!
            //boolean isALT_Key = (event.getModifiers() & ActionEvent.ALT_MASK) == ActionEvent.ALT_MASK;
            boolean isSHIFT_Key = (event.getModifiersEx() & ActionEvent.SHIFT_MASK) == ActionEvent.SHIFT_MASK || event.isShiftDown();

            int maxSize = 40;
            int minSize = 10;
            if (!isCTRL_Key && !isSHIFT_Key) {
                // showing popup menu
                showPopupMenu(sharedParameters, subTabsContainerHandler, event);
            } else if (isCTRL_Key && !isSHIFT_Key) {
                // Make it bigger and bold when middle click + ctrl
                if (subTabsContainerHandler.getFontSize() < maxSize) {
                    if (!subTabsContainerHandler.isBold())
                        subTabsContainerHandler.toggleBold(false);
                    subTabsContainerHandler.setFontSize(subTabsContainerHandler.getFontSize() + 2, false);
                    subTabsContainerHandler.hideCloseButton(false);
                }
            } else if (isCTRL_Key) {
                // Make it smaller but bold when middle click + ctrl + shift
                if (subTabsContainerHandler.getFontSize() > minSize) {
                    if (!subTabsContainerHandler.isBold())
                        subTabsContainerHandler.toggleBold(false);
                    subTabsContainerHandler.setFontSize(subTabsContainerHandler.getFontSize() - 2, false);
                    subTabsContainerHandler.hideCloseButton(false);
                }
            } else {
                // middle click with shift: should make it red and big and bold
                TabFeaturesObjectStyle tabFeaturesObjectStyle = new TabFeaturesObjectStyle("High: Red, Big, and Bold", "Arial", 18, true, false, false, Color.decode("#f71414"), "high", 18);
                subTabsContainerHandler.updateByTabFeaturesObjectStyle(tabFeaturesObjectStyle, false);
            }

            if (subTabsContainerHandler.getHasChanges()) {
                sharedParameters.allSettings.subTabsSettings.saveSettings(subTabsContainerHandler);
            }
        }
    }

    public static void addMouseWheelToJTabbedPane(SharpenerSharedParameters sharedParameters, BurpUITools.MainTabs currentToolTab, boolean isLastOneSelectable) {
        // from https://stackoverflow.com/questions/38463047/use-mouse-to-scroll-through-tabs-in-jtabbedpane

        MouseWheelListener mwl = e -> {
            JTabbedPane tabbedPane = (JTabbedPane) e.getSource();
            // works with version 2022.1.1 - not tested in the previous versions!
            int currentSelection = tabbedPane.getSelectedIndex();
            SubTabsContainerHandler subTabsContainerHandler = getSubTabContainerHandlerFromSharedParameters(sharedParameters, tabbedPane, currentSelection);

            if(subTabsContainerHandler == null)
                return;

            if (e.isControlDown()) {
                float currentFontSize = subTabsContainerHandler.getFontSize();

                if (e.getWheelRotation() < 0) {
                    //scrolled up
                    if (currentFontSize <= 36) {
                        subTabsContainerHandler.setFontSize(currentFontSize + 2, false);
                    }
                } else {
                    //scrolled down
                    if (currentFontSize >= 12) {
                        subTabsContainerHandler.setFontSize(currentFontSize - 2, false);
                    }
                }

                if (subTabsContainerHandler.getHasChanges()) {
                    sharedParameters.allSettings.subTabsSettings.saveSettings(subTabsContainerHandler);
                }
            } else if (e.isAltDown()) {    // experiment here
                subTabsContainerHandler.setIcon("alert", 16, true);
                sharedParameters.allSettings.subTabsSettings.saveSettings(subTabsContainerHandler);

            } else {
                e.isAltDown();
                if (false) { // mw+alt has been disabled as moved tabs won't be saved in the project file!
                    JComponent[] components = new JComponent[2];
                    JComponent[] tabComponents = new JComponent[2];
                    components[0] = (JComponent) tabbedPane.getSelectedComponent();
                    tabComponents[0] = (JComponent) tabbedPane.getTabComponentAt(currentSelection);


                    if (e.getWheelRotation() > 0) {
                        //scrolled down
                        int maxIndex = tabbedPane.getTabCount() - 2;
                        if (sharedParameters.isTabGroupSupportedByDefault)
                            maxIndex += 1;

                        if (currentSelection < maxIndex) {
                            components[1] = (JComponent) tabbedPane.getComponentAt(currentSelection + 1);
                            tabComponents[1] = (JComponent) tabbedPane.getTabComponentAt(currentSelection + 1);

    //*
                            try {
                                tabbedPane.remove(currentSelection + 1);
                            } catch (Exception err) {

                            }

                            try {
                                tabbedPane.remove(currentSelection);
                            } catch (Exception err) {

                            }

                            try {
                                tabbedPane.add(components[1], currentSelection);

                            } catch (Exception err) {

                            } finally {
                                tabbedPane.setTabComponentAt(currentSelection, tabComponents[1]);
                            }

                            try {
                                tabbedPane.add(components[0], currentSelection + 1);
                            } catch (Exception err) {

                            } finally {
                                tabbedPane.setTabComponentAt(currentSelection + 1, tabComponents[0]);
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
                            jumpToTabIndex(sharedParameters, subTabsContainerHandler, currentSelection + 1);


                            tabbedPane.revalidate();
                            tabbedPane.repaint();
                        }
                    } else {
                        //scrolled up
                        if (currentSelection > 0) {
                            components[1] = (JComponent) tabbedPane.getComponentAt(currentSelection - 1);
                            tabComponents[1] = (JComponent) tabbedPane.getTabComponentAt(currentSelection - 1);
    //*
                            try {
                                tabbedPane.remove(currentSelection);
                            } catch (Exception err) {

                            }

                            try {
                                tabbedPane.remove(currentSelection - 1);
                            } catch (Exception err) {

                            }

                            try {
                                tabbedPane.add(components[0], currentSelection - 1);
                            } catch (Exception err) {

                            } finally {
                                tabbedPane.setTabComponentAt(currentSelection - 1, tabComponents[0]);
                            }

                            try {
                                tabbedPane.add(components[1], currentSelection);
                            } catch (Exception err) {

                            } finally {
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


                            jumpToTabIndex(sharedParameters, subTabsContainerHandler, currentSelection - 1);


                            tabbedPane.revalidate();
                            tabbedPane.repaint();
                        }
                    }


                } else {
                    int offset = 0;
                    if (!isLastOneSelectable)
                        offset = 1;

                    int units = e.getWheelRotation();
                    int oldIndex = tabbedPane.getSelectedIndex();
                    int newIndex = oldIndex + units;
                    int chosenOne = newIndex;
                    int maxIndex = tabbedPane.getTabCount() - offset;

                    if (newIndex < 0)
                        chosenOne = 0;
                    else if (newIndex >= maxIndex)
                        chosenOne = maxIndex - 1;

                    SubTabsContainerHandler chosenOneSubTabsContainerHandler = getSubTabContainerHandlerFromSharedParameters(sharedParameters, tabbedPane, chosenOne);

                    while (chosenOneSubTabsContainerHandler == null || !tabbedPane.isEnabledAt(chosenOne) || !chosenOneSubTabsContainerHandler.isValid()
                            || chosenOneSubTabsContainerHandler.isGroupContainerTab() || !chosenOneSubTabsContainerHandler.isTitleVisible()) {
                        if (units > 0) {
                            //scroll down
                            chosenOne++;
                        } else {
                            //scroll up
                            chosenOne--;
                        }

                        int maxIndex2 = tabbedPane.getTabCount() - offset;

                        if (chosenOne < 0 || chosenOne >= maxIndex2) {
                            chosenOne = oldIndex;
                            break;
                        }
                        chosenOneSubTabsContainerHandler = getSubTabContainerHandlerFromSharedParameters(sharedParameters, tabbedPane, chosenOne);
                    }
                    jumpToTabIndex(sharedParameters, subTabsContainerHandler, chosenOne);
                }
            }

        };
        var currentToolTabbedPane = sharedParameters.get_toolTabbedPane(currentToolTab);
        if(currentToolTabbedPane != null)
            currentToolTabbedPane.addMouseWheelListener(mwl);
    }

    public static void removeMouseWheelFromJTabbedPane(SharpenerSharedParameters sharedParameters, BurpUITools.MainTabs currentToolTab, boolean onlyRemoveLast) {
        var currentToolTabbedPane = sharedParameters.get_toolTabbedPane(currentToolTab);
        if(currentToolTabbedPane != null) {
            MouseWheelListener[] mwlArr = currentToolTabbedPane.getMouseWheelListeners();
            for (int i = mwlArr.length - 1; i >= 0; i--) {
                currentToolTabbedPane.removeMouseWheelListener(mwlArr[i]);
                if (onlyRemoveLast) {
                    break;
                }
            }
        }
    }

    private static void setNotificationMenuMessage(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler, JMenuItem notificationMenuItem, String message) {
        if (currentSubTabsContainerHandler == null)
            return;

        if (sharedParameters.isFiltered(currentSubTabsContainerHandler.currentToolTab)) {

            if (!currentSubTabsContainerHandler.getVisible()) {
                message = "Filter: ON (" + sharedParameters.getHiddenSubTabsCount(currentSubTabsContainerHandler.currentToolTab) +
                        " hidden tabs) | THIS IS A HIDDEN TAB | " + message;
            } else {
                message = "Filter: ON (" + sharedParameters.getHiddenSubTabsCount(currentSubTabsContainerHandler.currentToolTab) +
                        " hidden tabs) | " + message;
            }

        } else {
            if (sharedParameters.burpMajorVersion < 2022
                    || (sharedParameters.burpMajorVersion == 2022 && sharedParameters.burpMinorVersion < 6)) { // hidden from version 2022.6
                message = "Filter: OFF | " + message;
            }
        }
        notificationMenuItem.setText(message);
    }

    private static JPopupMenu createPopupMenu(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler) {
        if (currentSubTabsContainerHandler == null)
            return new JPopupMenu();

        JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem notificationMenuItem = new JMenuItem();
        notificationMenuItem.setFont(notificationMenuItem.getFont().deriveFont(notificationMenuItem.getFont().getStyle() ^ Font.BOLD));
        setNotificationMenuMessage(sharedParameters, currentSubTabsContainerHandler, notificationMenuItem, "Tab Title: " + currentSubTabsContainerHandler.getTabTitle());

        notificationMenuItem.setEnabled(false);
        popupMenu.add(notificationMenuItem);
        popupMenu.addSeparator();

        if (!currentSubTabsContainerHandler.isDotDotDotTab()) {
            JMenuItem pasteStyleMenu = new JMenuItem("Paste Style");
            if (sharedParameters.copiedTabFeaturesObjectStyle == null) {
                pasteStyleMenu.setEnabled(false);
            }
            pasteStyleMenu.addActionListener(e -> {
                if (sharedParameters.copiedTabFeaturesObjectStyle != null) {
                    currentSubTabsContainerHandler.updateByTabFeaturesObjectStyle(sharedParameters.copiedTabFeaturesObjectStyle, true);
                    sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler);
                    sharedParameters.printDebugMessage("Style pasted...");
                }
            });
            popupMenu.add(pasteStyleMenu);

            JMenuItem copyStyleMenu = new JMenuItem("Copy Style");
            copyStyleMenu.addActionListener(e -> {
                sharedParameters.copiedTabFeaturesObjectStyle = currentSubTabsContainerHandler.getTabFeaturesObjectStyle();
                sharedParameters.printDebugMessage("Style copied...");
            });
            popupMenu.add(copyStyleMenu);

            JMenuItem pasteStyleSearchTitleMenu = new JMenuItem("Find/Paste Style (Use RegEx in Title)");
            if (sharedParameters.copiedTabFeaturesObjectStyle == null) {
                pasteStyleSearchTitleMenu.setEnabled(false);
            }
            pasteStyleSearchTitleMenu.addActionListener(e -> {
                if (sharedParameters.copiedTabFeaturesObjectStyle != null) {
                    String titleKeyword = UIHelper.showPlainInputMessage("Enter a Regular Expression (case insensitive):", "Search in titles and replace their style", sharedParameters.searchedTabTitleForPasteStyle, sharedParameters.get_mainFrameUsingMontoya());
                    if (!titleKeyword.isEmpty()) {
                        if (Utilities.isValidRegExPattern(titleKeyword)) {
                            sharedParameters.searchedTabTitleForPasteStyle = titleKeyword;
                            ArrayList<SubTabsContainerHandler> subTabsContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentSubTabsContainerHandler.currentToolTab);
                            for (SubTabsContainerHandler subTabsContainerHandlerItem : subTabsContainerHandlers) {
                                if (subTabsContainerHandlerItem.getVisible()) {
                                    String subTabTitle = subTabsContainerHandlerItem.getTabTitle();
                                    if (Pattern.compile(titleKeyword, Pattern.CASE_INSENSITIVE).matcher(subTabTitle).find()) {
                                        subTabsContainerHandlerItem.updateByTabFeaturesObjectStyle(sharedParameters.copiedTabFeaturesObjectStyle, true);
                                    }
                                }
                            }
                            sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler.currentToolTab);
                            sharedParameters.printDebugMessage("Style pasted in titles which matched: " + titleKeyword);
                        } else {
                            UIHelper.showWarningMessage("Regular expression was invalid.", sharedParameters.get_mainFrameUsingMontoya());
                            sharedParameters.printlnError("invalid regex: " + titleKeyword);
                        }
                    }

                }
            });
            popupMenu.add(pasteStyleSearchTitleMenu);

            JMenuItem pasteStyleForAllVisibleMenu = new JMenuItem("Paste Style For All Visible Tabs");
            if (sharedParameters.copiedTabFeaturesObjectStyle == null) {
                pasteStyleForAllVisibleMenu.setEnabled(false);
            }
            pasteStyleForAllVisibleMenu.addActionListener(e -> {
                int response = UIHelper.askConfirmMessage("Sharpener Extension: Changing all visible tabs' styles", "Are you sure you want to change all visible tab's style (you cannot undo this)?", new String[]{"Yes", "No"}, sharedParameters.get_mainFrameUsingMontoya());
                if (response == 0) {
                    if (sharedParameters.copiedTabFeaturesObjectStyle != null) {
                        ArrayList<SubTabsContainerHandler> subTabsContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentSubTabsContainerHandler.currentToolTab);
                        for (SubTabsContainerHandler subTabsContainerHandlerItem : subTabsContainerHandlers) {
                            if (subTabsContainerHandlerItem.getVisible()) {
                                subTabsContainerHandlerItem.updateByTabFeaturesObjectStyle(sharedParameters.copiedTabFeaturesObjectStyle, true);
                            }
                        }
                        sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler);
                        sharedParameters.printDebugMessage("Style pasted...");
                    }
                }
            });
            popupMenu.add(pasteStyleForAllVisibleMenu);

            JMenuItem defaultProfile = new JMenuItem("Reset to Default");
            defaultProfile.addActionListener(e -> {
                currentSubTabsContainerHandler.setToDefault(true);
                sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler);
            });
            if (currentSubTabsContainerHandler.isDefault())
                defaultProfile.setEnabled(false);
            popupMenu.add(defaultProfile);

            JMenu profileMenu = new JMenu("Predefined Styles");
            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "High - Confirmed", currentSubTabsContainerHandler.getFontName(), (int) currentSubTabsContainerHandler.getFontSize(), true, false, false, "#f71414", "high"));
            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "High - Unconfirmed", currentSubTabsContainerHandler.getFontName(), (int) currentSubTabsContainerHandler.getFontSize(), true, false, false, "#f71414", "high-tbc"));

            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "Medium - Confirmed", currentSubTabsContainerHandler.getFontName(), (int) currentSubTabsContainerHandler.getFontSize(), true, false, false, "#ff7e0d", "medium"));
            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "Medium - Unconfirmed", currentSubTabsContainerHandler.getFontName(), (int) currentSubTabsContainerHandler.getFontSize(), true, false, false, "#ff7e0d", "medium-tbc"));

            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "Low - Confirmed", currentSubTabsContainerHandler.getFontName(), (int) currentSubTabsContainerHandler.getFontSize(), true, false, false, "#FAD400", "low"));
            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "Low - Unconfirmed", currentSubTabsContainerHandler.getFontName(), (int) currentSubTabsContainerHandler.getFontSize(), true, false, false, "#FAD400", "low-tbc"));

            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "Info - Confirmed", currentSubTabsContainerHandler.getFontName(), (int) currentSubTabsContainerHandler.getFontSize(), true, true, false, "#0d9e1e", "info"));
            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "Info - Unconfirmed", currentSubTabsContainerHandler.getFontName(), (int) currentSubTabsContainerHandler.getFontSize(), true, true, false, "#0d9e1e", "info-tbc"));

            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "Interesting 1", currentSubTabsContainerHandler.getFontName(), (int) currentSubTabsContainerHandler.getFontSize(), true, true, false, "#395EEA", "interesting"));
            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "Interesting 2", currentSubTabsContainerHandler.getFontName(), (int) currentSubTabsContainerHandler.getFontSize(), true, true, false, "#D641CF", "interesting2"));

            /*
            // originals:
            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "High - Confirmed", "Arial", 18, true, false, false, "#f71414", "high"));
            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "High - Unconfirmed", "Arial", 18, true, false, false, "#f71414", "high-tbc"));

            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "Medium - Confirmed", "Arial", 18, true, false, false, "#ff7e0d", "medium"));
            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "Medium - Unconfirmed", "Arial", 18, true, false, false, "#ff7e0d", "medium-tbc"));

            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "Low - Confirmed", "Arial", 16, true, false, false, "#FAD400", "low"));
            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "Low - Unconfirmed", "Arial", 16, true, false, false, "#FAD400", "low-tbc"));

            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "Info - Confirmed", "Arial", 16, true, true, false, "#0d9e1e", "info"));
            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "Info - Unconfirmed", "Arial", 16, true, true, false, "#0d9e1e", "info-tbc"));

            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "Interesting 1", "Arial", 16, true, true, false, "#395EEA", "interesting"));
            profileMenu.add(predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, "Interesting 2", "Arial", 16, true, true, false, "#D641CF", "interesting2"));
            */
            profileMenu.add(predefinedStyleMenuByIcon(sharedParameters, currentSubTabsContainerHandler, "False Positive", "false-positive"));
            profileMenu.add(predefinedStyleMenuByIcon(sharedParameters, currentSubTabsContainerHandler, "Duplicate", "duplicate"));
            profileMenu.add(predefinedStyleMenuByIcon(sharedParameters, currentSubTabsContainerHandler, "Tick", "tick"));
            profileMenu.add(predefinedStyleMenuByIcon(sharedParameters, currentSubTabsContainerHandler, "Cross", "cross"));
            popupMenu.add(profileMenu);

            JMenu customStyleMenu = new JMenu("Custom Style");
            if (sharedParameters.burpMajorVersion < 2022
                    || (sharedParameters.burpMajorVersion == 2022 && sharedParameters.burpMinorVersion < 6)) { // This does not work in version 2022.6 for unknown reasons
                JCheckBoxMenuItem closeButtonMenuItem = new JCheckBoxMenuItem("Remove Close Button");
                closeButtonMenuItem.addActionListener(e -> {
                    currentSubTabsContainerHandler.setVisibleCloseButton(!closeButtonMenuItem.isSelected(), true);
                    sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler);
                });
                closeButtonMenuItem.setSelected(!currentSubTabsContainerHandler.getVisibleCloseButton());
                customStyleMenu.add(closeButtonMenuItem);
            }

            JMenu fontNameMenu = new JScrollMenu("Font Name");
            String[] fonts = GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames();

            for (String font : fonts) {
                JCheckBoxMenuItem fontNameItem = new JCheckBoxMenuItem(font);
                fontNameItem.setSelected(font.equalsIgnoreCase(currentSubTabsContainerHandler.getFontName()));
                fontNameItem.addActionListener(e -> {
                    currentSubTabsContainerHandler.setFontName(font, true);
                    sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler);

                });
                fontNameMenu.add(fontNameItem);
            }
            customStyleMenu.add(fontNameMenu);

            JMenu fontSizeMenu = new JMenu("Font Size");
            float minFontSize = 10, maxFontSize = 40;
            for (float fontSize = minFontSize; fontSize < maxFontSize; fontSize += 2) {
                JCheckBoxMenuItem sizeItem = new JCheckBoxMenuItem(fontSize + "");
                sizeItem.setSelected(currentSubTabsContainerHandler.getFontSize() == fontSize);
                float finalFontSize = fontSize;
                sizeItem.addActionListener(e -> {
                    currentSubTabsContainerHandler.setFontSize(finalFontSize, true);
                    sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler);
                });
                fontSizeMenu.add(sizeItem);
            }
            customStyleMenu.add(fontSizeMenu);

            JCheckBoxMenuItem boldMenu = new JCheckBoxMenuItem("Bold");
            boldMenu.setSelected(currentSubTabsContainerHandler.isBold());
            boldMenu.addActionListener(e -> {
                currentSubTabsContainerHandler.toggleBold(true);
                sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler);
            });
            customStyleMenu.add(boldMenu);

            JCheckBoxMenuItem italicMenu = new JCheckBoxMenuItem("Italic");
            italicMenu.setSelected(currentSubTabsContainerHandler.isItalic());
            italicMenu.addActionListener(e -> {
                currentSubTabsContainerHandler.toggleItalic(true);
                sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler);
            });
            customStyleMenu.add(italicMenu);


            Resource[] resourceIcons = new Resource[]{};

            try {
                PathMatchingResourcePatternResolver resolver = new PathMatchingResourcePatternResolver(sharedParameters.extensionClass.getClassLoader());
                resourceIcons = resolver.getResources("classpath:subtabicons/*.*");

            } catch (IOException e) {
                sharedParameters.printDebugMessage("No icon was found in resources");
            }

            JMenu changeTabIcon = new JScrollMenu("Icon");

            ButtonGroup subTabIconGroup = new ButtonGroup();

            JRadioButtonMenuItem noneIconImage = new JRadioButtonMenuItem("None");
            if (!currentSubTabsContainerHandler.hasIcon()) {
                noneIconImage.setSelected(true);
            }
            noneIconImage.addActionListener(new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    currentSubTabsContainerHandler.removeIcon(false);
                    sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler);
                }
            });
            subTabIconGroup.add(noneIconImage);
            changeTabIcon.add(noneIconImage);

            for (Resource resourceIcon : resourceIcons) {
                if(resourceIcon == null)
                    continue;

                String resourcePath = "/subtabicons/" + resourceIcon.getFilename();
                JRadioButtonMenuItem subTabIconImage = new JRadioButtonMenuItem(Objects.requireNonNull(resourceIcon.getFilename()).replaceAll("\\..*$", ""));
                subTabIconImage.setIcon(new ImageIcon(Objects.requireNonNull(ImageHelper.scaleImageToWidth(ImageHelper.loadImageResource(sharedParameters.extensionClass, resourcePath), 32))));
                String fileNameWithOutExt = Files.getNameWithoutExtension(resourceIcon.getFilename());

                if (fileNameWithOutExt.equalsIgnoreCase(currentSubTabsContainerHandler.getIconString())) {
                    subTabIconImage.setSelected(true);
                }
                subTabIconImage.addActionListener((e) -> {
                    currentSubTabsContainerHandler.setIcon(fileNameWithOutExt, (int) currentSubTabsContainerHandler.getFontSize(), false);
                    sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler);
                });
                subTabIconGroup.add(subTabIconImage);
                changeTabIcon.add(subTabIconImage);
            }
            customStyleMenu.add(changeTabIcon);

            JMenuItem colorMenu = new JMenuItem("Set Foreground Color");
            colorMenu.addActionListener(e -> {
                JColorChooser colorChooser = new JColorChooser();
                // we only want to keep the Swatches panel
                AbstractColorChooserPanel[] panels = colorChooser.getChooserPanels();
                for (AbstractColorChooserPanel p : panels) {
                    String displayName = p.getDisplayName();
                    switch (displayName) {
                        //case "RGB":
                        case "HSL":
                        case "HSV":
                        case "CMYK":
                            colorChooser.removeChooserPanel(p);
                            break;
                    }
                }

                colorChooser.setColor(currentSubTabsContainerHandler.getColor());
                JDialog dialog = JColorChooser.createDialog(
                        sharedParameters.get_mainFrameUsingMontoya(),
                        "Choose a Color",
                        true,
                        colorChooser,
                        null,
                        null);
                dialog.setVisible(true);
                if (colorChooser.getColor() != null) {
                    currentSubTabsContainerHandler.setColor(colorChooser.getColor(), true);
                    sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler);
                }
            });
            customStyleMenu.add(colorMenu);
            popupMenu.add(customStyleMenu);

            popupMenu.addSeparator();
        }

        JMenu searchAndJumpMenu = new JMenu("Find Title (Use RegEx)");

        JMenuItem searchAndJumpDefineRegExMenu = new JMenuItem("Search by RegEx (case insensitive) [Ctrl+Shift+F]");

        searchAndJumpDefineRegExMenu.addActionListener(e -> {
            defineRegExPopupForSearchAndJump(sharedParameters, currentSubTabsContainerHandler);
        });
        searchAndJumpMenu.add(searchAndJumpDefineRegExMenu);

        JMenuItem jumpToNextTabByTitleMenu = new JMenuItem("Next" + " [F3]");
        if (sharedParameters.searchedTabTitleForJumpToTab.isEmpty()) {
            jumpToNextTabByTitleMenu.setEnabled(false);
        } else {
            jumpToNextTabByTitleMenu.setToolTipText("Search for: " + sharedParameters.searchedTabTitleForJumpToTab);
        }

        jumpToNextTabByTitleMenu.addActionListener(e -> {
            searchInTabTitlesAndJump(sharedParameters, currentSubTabsContainerHandler, notificationMenuItem, true);
        });
        searchAndJumpMenu.add(jumpToNextTabByTitleMenu);

        JMenuItem jumpToPreviousTabByTitleMenu = new JMenuItem("Previous" + " [Shift+F3]");
        if (sharedParameters.searchedTabTitleForJumpToTab.isEmpty()) {
            jumpToPreviousTabByTitleMenu.setEnabled(false);
        } else {
            jumpToPreviousTabByTitleMenu.setToolTipText("Search for: " + sharedParameters.searchedTabTitleForJumpToTab);
        }

        jumpToPreviousTabByTitleMenu.addActionListener(e -> {
            searchInTabTitlesAndJump(sharedParameters, currentSubTabsContainerHandler, notificationMenuItem, false);
        });

        searchAndJumpMenu.add(jumpToPreviousTabByTitleMenu);

        if (sharedParameters.searchedTabTitleForJumpToTab.isEmpty()) {
            searchAndJumpMenu.setText("Find Title (Click > Use RegEx)");

            searchAndJumpMenu.addMouseListener(new MouseAdapterExtensionHandler(mouseEvent -> {
                if (SwingUtilities.isLeftMouseButton(mouseEvent)) {
                    searchAndJumpDefineRegExMenu.doClick();
                    popupMenu.setVisible(false);

                }
            }, MouseEvent.MOUSE_CLICKED));
        } else {
            // we want to rename searchAndJumpMenu, so it shows what would happen when it is clicked!
            searchAndJumpMenu.setText("Find Title (Click > Next, Right-Click > Prev)");

            searchAndJumpMenu.addMouseListener(new MouseAdapterExtensionHandler(mouseEvent -> {
                if (SwingUtilities.isRightMouseButton(mouseEvent)) {
                    jumpToPreviousTabByTitleMenu.doClick();
                } else {
                    jumpToNextTabByTitleMenu.doClick();
                }
            }, MouseEvent.MOUSE_CLICKED));
        }

        popupMenu.add(searchAndJumpMenu);

        if (sharedParameters.burpMajorVersion < 2022
                || (sharedParameters.burpMajorVersion == 2022 && sharedParameters.burpMinorVersion < 6)) { // hidden from version 2022.6
            JMenu filterTitleMenu = new JMenu("Filter Titles (Click > Use RegEx)");

            JMenuItem removeFilterTitle = new JMenuItem("Show All");
            if (!sharedParameters.isFiltered(currentSubTabsContainerHandler.currentToolTab)) {
                removeFilterTitle.setEnabled(false);
            }
            removeFilterTitle.addActionListener(new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    showAllTabTitles(sharedParameters, currentSubTabsContainerHandler);
                }
            });
            filterTitleMenu.add(removeFilterTitle);

            JMenuItem toggleCurrentTabVisibilityFilterTitle = new JMenuItem("Toggle Current Tab Visibility");
            toggleCurrentTabVisibilityFilterTitle.addActionListener(new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    toggleCurrentTabVisibility(sharedParameters, currentSubTabsContainerHandler);
                }
            });
            filterTitleMenu.add(toggleCurrentTabVisibilityFilterTitle);

            filterTitleMenu.addSeparator();

            JMenuItem defineFilterTitleRegEx = new JMenuItem("Define RegEx (case insensitive)");
            defineFilterTitleRegEx.addActionListener(new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    String titleKeyword = UIHelper.showPlainInputMessage("Enter a Regular Expression:", "Filter Titles", sharedParameters.titleFilterRegEx, sharedParameters.get_mainFrameUsingMontoya());
                    if (!titleKeyword.isEmpty()) {
                        if (Utilities.isValidRegExPattern(titleKeyword)) {
                            showAllTabTitles(sharedParameters, currentSubTabsContainerHandler);
                            sharedParameters.titleFilterRegEx = titleKeyword;
                            sharedParameters.filterOperationMode.put(currentSubTabsContainerHandler.currentToolTab, 0);
                            setTabTitleFilter(sharedParameters, currentSubTabsContainerHandler);
                        } else {
                            UIHelper.showWarningMessage("Regular expression was invalid.", sharedParameters.get_mainFrameUsingMontoya());
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
                    showAllTabTitles(sharedParameters, currentSubTabsContainerHandler);
                    sharedParameters.titleFilterRegEx = "^(#\\d+\\s+)?\\s*\\d+\\s*$";
                    sharedParameters.filterOperationMode.put(currentSubTabsContainerHandler.currentToolTab, 0);
                    setTabTitleFilter(sharedParameters, currentSubTabsContainerHandler);
                }
            });
            filterTitleMenu.add(numericalFilterTitle);

            JMenuItem customStylesFilterTitle = new JMenuItem("Custom Styles");
            customStylesFilterTitle.addActionListener(new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    showAllTabTitles(sharedParameters, currentSubTabsContainerHandler);
                    sharedParameters.titleFilterRegEx = "";
                    sharedParameters.filterOperationMode.put(currentSubTabsContainerHandler.currentToolTab, 1);
                    setTabTitleFilter(sharedParameters, currentSubTabsContainerHandler);
                }
            });
            filterTitleMenu.add(customStylesFilterTitle);

            JMenuItem customStylesOrCustomNamesFilterTitle = new JMenuItem("Custom Styles or Not Numerical Titles");
            customStylesOrCustomNamesFilterTitle.addActionListener(new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    showAllTabTitles(sharedParameters, currentSubTabsContainerHandler);
                    sharedParameters.titleFilterRegEx = "^(#\\d+\\s+)?\\s*\\d+\\s*$";
                    sharedParameters.filterOperationMode.put(currentSubTabsContainerHandler.currentToolTab, 2);
                    setTabTitleFilter(sharedParameters, currentSubTabsContainerHandler);
                }
            });
            filterTitleMenu.add(customStylesOrCustomNamesFilterTitle);

            JMenuItem webSocketFilterTitle = new JMenuItem("Websocket Tabs");
            webSocketFilterTitle.addActionListener(new AbstractAction() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    showAllTabTitles(sharedParameters, currentSubTabsContainerHandler);
                    sharedParameters.titleFilterRegEx = "";
                    sharedParameters.filterOperationMode.put(currentSubTabsContainerHandler.currentToolTab, 3);
                    setTabTitleFilter(sharedParameters, currentSubTabsContainerHandler);
                }
            });
            filterTitleMenu.add(webSocketFilterTitle);

            filterTitleMenu.addSeparator();


            JCheckBoxMenuItem filterTitleMenuNegativeSearch = new JCheckBoxMenuItem("Use Negative Logic");
            filterTitleMenuNegativeSearch.setState(sharedParameters.isTitleFilterNegative);

            filterTitleMenuNegativeSearch.addActionListener(e -> {
                sharedParameters.isTitleFilterNegative = !sharedParameters.isTitleFilterNegative;
                showAllTabTitles(sharedParameters, currentSubTabsContainerHandler);
                setTabTitleFilter(sharedParameters, currentSubTabsContainerHandler);
            });

            filterTitleMenu.add(filterTitleMenuNegativeSearch);

            if (sharedParameters.isFiltered(currentSubTabsContainerHandler.currentToolTab)) {
                filterTitleMenu.setText("Filter Titles (Click > Use RegEx, Right-Click > Show All)");
                filterTitleMenu.addMouseListener(new MouseAdapterExtensionHandler(mouseEvent -> {
                    if (SwingUtilities.isRightMouseButton(mouseEvent)) {
                        removeFilterTitle.doClick();
                        popupMenu.setVisible(false);
                    } else {
                        defineFilterTitleRegEx.doClick();
                        popupMenu.setVisible(false);
                    }
                }, MouseEvent.MOUSE_CLICKED));
            } else {
                filterTitleMenu.addMouseListener(new MouseAdapterExtensionHandler(mouseEvent -> {
                    if (!SwingUtilities.isRightMouseButton(mouseEvent)) {
                        defineFilterTitleRegEx.doClick();
                        popupMenu.setVisible(false);
                    }
                }, MouseEvent.MOUSE_CLICKED));
            }


            popupMenu.add(filterTitleMenu);

        }

        JMenuItem copyTitleMenu = new JMenuItem("Copy Title [Ctrl+C]");
        copyTitleMenu.addActionListener(e -> {
            copyTitle(sharedParameters, currentSubTabsContainerHandler);
        });
        popupMenu.add(copyTitleMenu);

        JMenuItem pasteTitleMenu = new JMenuItem("Paste Title [Ctrl+V]");

        try {
            String clipboardText = (String) Toolkit.getDefaultToolkit()
                    .getSystemClipboard().getData(DataFlavor.stringFlavor);
            sharedParameters.lastClipboardText = clipboardText.trim().replaceAll("^#\\d+\\s+", "");
        } catch (Exception e) {
            sharedParameters.lastClipboardText = "";
        }

        if (sharedParameters.lastClipboardText.isBlank()) {
            pasteTitleMenu.setEnabled(false);
        } else {
            pasteTitleMenu.setToolTipText("Clipboard value: " + StringUtils.abbreviate(sharedParameters.lastClipboardText, 100));
        }

        pasteTitleMenu.addActionListener(e -> {
            pasteTitle(sharedParameters, currentSubTabsContainerHandler);
        });
        popupMenu.add(pasteTitleMenu);

        JMenuItem renameTitleMenu = new JMenuItem("Rename Title [F2]");
        renameTitleMenu.addActionListener(e -> {
            renameTitle(sharedParameters, currentSubTabsContainerHandler);
        });
        popupMenu.add(renameTitleMenu);


        JMenuItem matchReplaceTitleMenu = new JMenuItem("Match/Replace Titles (Use RegEx)");
        matchReplaceTitleMenu.addActionListener(e -> {
            String[] matchReplaceResult = UIHelper.showPlainInputMessages(new String[]{"Find what (start it with `(?i)` for case insensitive RegEx):", "Replace with:"}, "Title Match and Replace (RegEx)", new String[]{sharedParameters.matchReplaceTitle_RegEx, sharedParameters.matchReplaceTitle_ReplaceWith}, sharedParameters.get_mainFrameUsingMontoya());
            sharedParameters.matchReplaceTitle_RegEx = (matchReplaceResult[0] != null) ? matchReplaceResult[0] : "";
            sharedParameters.matchReplaceTitle_ReplaceWith = (matchReplaceResult[1] != null) ? matchReplaceResult[1] : "";
            if (!sharedParameters.matchReplaceTitle_RegEx.isEmpty()) {
                if (Utilities.isValidRegExPattern(sharedParameters.matchReplaceTitle_RegEx)) {
                    ArrayList<SubTabsContainerHandler> subTabsContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentSubTabsContainerHandler.currentToolTab);
                    for (SubTabsContainerHandler subTabsContainerHandlerItem : subTabsContainerHandlers) {
                        if (subTabsContainerHandlerItem.getVisible()) {
                            String subTabTitle = subTabsContainerHandlerItem.getTabTitle();
                            if (Pattern.compile(sharedParameters.matchReplaceTitle_RegEx).matcher(subTabTitle).find()) {
                                subTabsContainerHandlerItem.setTabTitle(subTabsContainerHandlerItem.getTabTitle().replaceAll(sharedParameters.matchReplaceTitle_RegEx, sharedParameters.matchReplaceTitle_ReplaceWith), true);
                            }
                        }
                    }
                    sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler.currentToolTab);
                    sharedParameters.printDebugMessage("Match and replace titles finished. -RegEx: " + sharedParameters.matchReplaceTitle_RegEx + " -Replace with: " + sharedParameters.matchReplaceTitle_ReplaceWith);
                } else {
                    UIHelper.showWarningMessage("Regular expression was invalid.", sharedParameters.get_mainFrameUsingMontoya());
                    sharedParameters.printlnError("invalid regex: " + sharedParameters.matchReplaceTitle_RegEx);
                }
            }
        });
        popupMenu.add(matchReplaceTitleMenu);

        JMenu previousTitlesMenu = new JMenu("Previous Titles");

        JMenu previousTitlesMenuSet = new JMenu("Set");
        JMenu previousTitlesMenuCopy = new JMenu("Copy");
        JMenuItem previousTitlesMenuClearHistory = new JMenuItem("Clear History");

        if (currentSubTabsContainerHandler.getTitleHistory().length <= 1) {
            previousTitlesMenu.setEnabled(false);
            previousTitlesMenuSet.setEnabled(false);
            previousTitlesMenuCopy.setEnabled(false);
            previousTitlesMenuClearHistory.setEnabled(false);
        } else {
            String[] uniqueInvertedTitleHistoryArray = currentSubTabsContainerHandler.getTitleHistory();

            for (String tempPrevTitle : uniqueInvertedTitleHistoryArray) {
                if (!tempPrevTitle.equalsIgnoreCase(currentSubTabsContainerHandler.getTabTitle())) {
                    JMenuItem previousTitleMenuSet = new JMenuItem(new AbstractAction(tempPrevTitle) {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            currentSubTabsContainerHandler.setTabTitle(tempPrevTitle, true);
                            sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler);
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
                    currentSubTabsContainerHandler.setTitleHistory(null);
                    sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler);
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
            jumpToFirstTab(sharedParameters, currentSubTabsContainerHandler);
        });


        jumpMenu.add(jumpToFirstTabMenu);

        JMenuItem jumpToLastTabMenu = new JMenuItem("Last Tab [End]");

        jumpToLastTabMenu.addActionListener(e -> {
            jumpToLastTab(sharedParameters, currentSubTabsContainerHandler);
        });

        jumpMenu.add(jumpToLastTabMenu);

        JMenuItem jumpToPreviousTabMenu = new JMenuItem("Previous Tab [Left Arrow]");

        jumpToPreviousTabMenu.addActionListener(e -> {
            jumpToPreviousTab(sharedParameters, currentSubTabsContainerHandler, notificationMenuItem);
        });

        jumpMenu.add(jumpToPreviousTabMenu);

        JMenuItem jumpToNextTabMenu = new JMenuItem("Next Tab [Right Arrow]");
        jumpToNextTabMenu.addActionListener(e -> {
            jumpToNextTab(sharedParameters, currentSubTabsContainerHandler, notificationMenuItem);
        });
        jumpMenu.add(jumpToNextTabMenu);

        JMenuItem jumpToPreviouslySelectedTabMenu = new JMenuItem("Back [Alt+Left Arrow]");
        if (sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabsContainerHandler.currentToolTab).size() <= 0)
            jumpToPreviouslySelectedTabMenu.setEnabled(false);
        jumpToPreviouslySelectedTabMenu.addActionListener(e -> {
            jumpToPreviouslySelectedTab(sharedParameters, currentSubTabsContainerHandler, notificationMenuItem);
        });
        jumpMenu.add(jumpToPreviouslySelectedTabMenu);

        JMenuItem jumpToNextlySelectedTabMenu = new JMenuItem("Forward [Alt+Right Arrow]");
        if (sharedParameters.subTabNextlySelectedIndexHistory.get(currentSubTabsContainerHandler.currentToolTab).size() <= 0)
            jumpToNextlySelectedTabMenu.setEnabled(false);
        jumpToNextlySelectedTabMenu.addActionListener(e -> {
            jumpToNextlySelectedTab(sharedParameters, currentSubTabsContainerHandler, notificationMenuItem);
        });
        jumpMenu.add(jumpToNextlySelectedTabMenu);


        jumpMenu.addMouseListener(new MouseAdapterExtensionHandler(mouseEvent -> {
            if (SwingUtilities.isRightMouseButton(mouseEvent)) {
                jumpToPreviousTabMenu.doClick();
            } else {
                jumpToNextTabMenu.doClick();
            }
        }, MouseEvent.MOUSE_CLICKED));

        popupMenu.add(jumpMenu);

        JMenu tabScreenshotMenu = new JMenu("Capture Screenshot");
        JMenuItem saveScreenshotToClipboardMenu = new JMenuItem("Clipboard");
        saveScreenshotToClipboardMenu.addActionListener(e -> {

            Rectangle componentRect = currentSubTabsContainerHandler.parentTabbedPane.getSelectedComponent().getBounds();
            BufferedImage bufferedImage = new BufferedImage(componentRect.width, componentRect.height, BufferedImage.TYPE_INT_RGB);
            currentSubTabsContainerHandler.parentTabbedPane.getSelectedComponent().paint(bufferedImage.getGraphics());
            ImageHelper.setClipboard(bufferedImage);
        });
        tabScreenshotMenu.add(saveScreenshotToClipboardMenu);

        JMenuItem saveScreenshotToFileMenu = new JMenuItem("File");
        saveScreenshotToFileMenu.addActionListener(e -> {
            Rectangle componentRect = currentSubTabsContainerHandler.parentTabbedPane.getSelectedComponent().getBounds();
            BufferedImage bufferedImage = new BufferedImage(componentRect.width, componentRect.height, BufferedImage.TYPE_INT_ARGB);
            currentSubTabsContainerHandler.parentTabbedPane.getSelectedComponent().paint(bufferedImage.getGraphics());

            String saveLocation = UIHelper.showDirectorySaveDialog(sharedParameters.allSettings.subTabsSettings.lastSavedImageLocation, sharedParameters.get_mainFrameUsingMontoya());

            if (!saveLocation.isEmpty()) {
                sharedParameters.allSettings.subTabsSettings.lastSavedImageLocation = saveLocation;
                String strDate = new SimpleDateFormat("yyyyMMddHHmmss").format(new Date());
                String imageFileLocation = saveLocation + "/" + currentSubTabsContainerHandler.getTabTitle().replaceAll("[^a-zA-Z0-9-_.]", "_") + "_" + strDate + ".png";

                try {
                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    ImageIO.write(bufferedImage, "png", os);
                    try (OutputStream outputStream = new FileOutputStream(imageFileLocation)) {
                        os.writeTo(outputStream);
                    }
                } catch (Exception err) {
                    sharedParameters.printlnError("Image file could not be saved: " + imageFileLocation);
                    sharedParameters.printDebugMessage(err.getMessage());
                }

                File imageFile = new File(imageFileLocation);
                if (imageFile.exists()) {
                    sharedParameters.printlnOutput("Image file saved successfully: " + imageFileLocation);
                } else {
                    sharedParameters.printlnError("Image file could not be saved: " + imageFileLocation);
                    UIHelper.showWarningMessage("Image file could not be saved: " + imageFileLocation, sharedParameters.get_mainFrameUsingMontoya());
                }

            }
        });
        tabScreenshotMenu.add(saveScreenshotToFileMenu);
        popupMenu.add(tabScreenshotMenu);

        if (!sharedParameters.isTabGroupSupportedByDefault) {
            JMenuItem jumpToAddTabMenu = new JMenuItem("Add an Empty New Tab");

            jumpToAddTabMenu.addActionListener(actionEvent -> {

                Container dotdotdotTabContainer = (Container) currentSubTabsContainerHandler.parentTabbedPane.getTabComponentAt(currentSubTabsContainerHandler.parentTabbedPane.getTabCount() - 1);

                // this is a hack to get the Y location of the ... tab!
                int x = dotdotdotTabContainer.getLocationOnScreen().x + dotdotdotTabContainer.getWidth() / 2;
                int burp_x = dotdotdotTabContainer.getParent().getLocationOnScreen().x + dotdotdotTabContainer.getParent().getWidth() - dotdotdotTabContainer.getWidth() / 2;
                if (x > burp_x) {
                    x = burp_x;
                }

                int y = dotdotdotTabContainer.getLocationOnScreen().y + dotdotdotTabContainer.getHeight() / 2;
                int burp_y = dotdotdotTabContainer.getParent().getLocationOnScreen().y + dotdotdotTabContainer.getParent().getHeight() - dotdotdotTabContainer.getHeight() / 2;
                if (y > burp_y || y < burp_y - dotdotdotTabContainer.getHeight()) {
                    y = burp_y;
                }

                try {
                    Robot robot = new Robot();
                    robot.mouseMove(x, y);
                } catch (Exception errRobot) {
                    sharedParameters.printlnError("Could not change mouse location: " + errRobot.getMessage());
                }

                jumpToPreviouslySelectedTab(sharedParameters, currentSubTabsContainerHandler, notificationMenuItem);

                jumpToTabIndex(sharedParameters, currentSubTabsContainerHandler, currentSubTabsContainerHandler.parentTabbedPane.getTabCount() - 1);
            });

            popupMenu.add(jumpToAddTabMenu);
        }

        popupMenu.addSeparator();

        BurpUITools.MainTabs tool = currentSubTabsContainerHandler.currentToolTab;

        if (sharedParameters.subTabSupportedTabs.contains(tool)) {
            if (sharedParameters.burpMajorVersion < 2022
                    || (sharedParameters.burpMajorVersion == 2022 && sharedParameters.burpMinorVersion < 6)) { // hidden from version 2022.6
                JCheckBoxMenuItem toolSubTabPaneScrollableLayout = new JCheckBoxMenuItem("Scrollable " + tool + " Tabs");
                if (sharedParameters.preferences.safeGetBooleanSetting("isScrollable_" + tool)) {
                    toolSubTabPaneScrollableLayout.setSelected(true);
                }

                toolSubTabPaneScrollableLayout.addActionListener((e) -> {
                    if (sharedParameters.preferences.safeGetBooleanSetting("isScrollable_" + tool)) {
                        SwingUtilities.invokeLater(() -> currentSubTabsContainerHandler.parentTabbedPane.setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT));
                        sharedParameters.preferences.safeSetSetting("isScrollable_" + tool, false);
                    } else {
                        SwingUtilities.invokeLater(() -> {
                            currentSubTabsContainerHandler.parentTabbedPane.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
                            new java.util.Timer().schedule(
                                    new java.util.TimerTask() {
                                        @Override
                                        public void run() {
                                            jumpToTabIndex(sharedParameters, currentSubTabsContainerHandler, 0);
                                            jumpToTabIndex(sharedParameters, currentSubTabsContainerHandler, currentSubTabsContainerHandler.getTabIndex());
                                        }
                                    },
                                    1000
                            );
                        });
                        sharedParameters.preferences.safeSetSetting("isScrollable_" + tool, true);
                    }
                });

                popupMenu.add(toolSubTabPaneScrollableLayout);

                JCheckBoxMenuItem toolSubTabPaneTabMinimizeTabSize = new JCheckBoxMenuItem("Minimize " + tool + " Tabs' Size");
                if (sharedParameters.preferences.safeGetBooleanSetting("minimizeSize_" + tool)) {
                    toolSubTabPaneTabMinimizeTabSize.setSelected(true);
                }

                toolSubTabPaneTabMinimizeTabSize.addActionListener((e) -> {
                    if (sharedParameters.preferences.safeGetBooleanSetting("minimizeSize_" + tool)) {
                        changeToolTabbedPaneUI_safe(sharedParameters, currentSubTabsContainerHandler, false);
                        sharedParameters.preferences.safeSetSetting("minimizeSize_" + tool, false);
                    } else {
                        changeToolTabbedPaneUI_safe(sharedParameters, currentSubTabsContainerHandler, false);
                        sharedParameters.preferences.safeSetSetting("minimizeSize_" + tool, true);
                    }
                });
                popupMenu.add(toolSubTabPaneTabMinimizeTabSize);

                JCheckBoxMenuItem toolSubTabPaneTabFixedPositionLayout = new JCheckBoxMenuItem("Fixed Tab Position for " + tool);
                if (sharedParameters.preferences.safeGetBooleanSetting("isTabFixedPosition_" + tool)) {
                    toolSubTabPaneTabFixedPositionLayout.setSelected(true);
                }

                toolSubTabPaneTabFixedPositionLayout.addActionListener((e) -> {
                    if (sharedParameters.preferences.safeGetBooleanSetting("isTabFixedPosition_" + tool)) {
                        changeToolTabbedPaneUI_safe(sharedParameters, currentSubTabsContainerHandler, false);
                        sharedParameters.preferences.safeSetSetting("isTabFixedPosition_" + tool, false);
                    } else {
                        changeToolTabbedPaneUI_safe(sharedParameters, currentSubTabsContainerHandler, false);
                        sharedParameters.preferences.safeSetSetting("isTabFixedPosition_" + tool, true);
                    }
                });
                popupMenu.add(toolSubTabPaneTabFixedPositionLayout);

            }

            JCheckBoxMenuItem toolSubTabPaneMouseWheelScroll = new JCheckBoxMenuItem("Activate Mouse Wheel: MW > Scroll, MW+Ctrl > Resize");
            if (sharedParameters.preferences.safeGetBooleanSetting("mouseWheelToScroll_" + tool)) {
                toolSubTabPaneMouseWheelScroll.setSelected(true);
            }

            toolSubTabPaneMouseWheelScroll.addActionListener((e) -> {
                if (sharedParameters.preferences.safeGetBooleanSetting("mouseWheelToScroll_" + tool)) {
                    SubTabsActions.removeMouseWheelFromJTabbedPane(sharedParameters, tool, true);
                    sharedParameters.preferences.safeSetSetting("mouseWheelToScroll_" + tool, false);
                } else {
                    SubTabsActions.addMouseWheelToJTabbedPane(sharedParameters, tool, sharedParameters.isTabGroupSupportedByDefault);
                    sharedParameters.preferences.safeSetSetting("mouseWheelToScroll_" + tool, true);
                }
            });

            popupMenu.add(toolSubTabPaneMouseWheelScroll);
        }

        return popupMenu;
    }

    private static JMenuItem predefinedStyleMenuByIcon(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler, String text, String iconString) {
        return predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, text, currentSubTabsContainerHandler.getFontName(), (int) currentSubTabsContainerHandler.getFontSize(), currentSubTabsContainerHandler.isBold(), currentSubTabsContainerHandler.isItalic(), currentSubTabsContainerHandler.getVisibleCloseButton(), currentSubTabsContainerHandler.getColorCode(), iconString);
    }

    private static JMenuItem predefinedStyleMenu(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler, String text, String fontName, int fontSize, boolean isBold, boolean isItalic, boolean isCloseButtonVisible, String colorCode, String iconString) {
        if (currentSubTabsContainerHandler == null)
            return null;

        JMenuItem profile = new JMenuItem(text);
        int style = profile.getFont().getStyle();

        if (isBold)
            style ^= Font.BOLD;

        if (isItalic)
            style ^= Font.ITALIC;

        profile.setFont(new Font(fontName, style, fontSize));
        profile.setForeground(Color.decode(colorCode));
        profile.setIcon(new ImageIcon(Objects.requireNonNull(ImageHelper.scaleImageToWidth(ImageHelper.loadImageResource(sharedParameters.extensionClass, "subtabicons/" + iconString + ".png"), fontSize))));
        profile.addActionListener(e -> {
            TabFeaturesObjectStyle tabFeaturesObjectStyle = new TabFeaturesObjectStyle(text, fontName, fontSize, isBold, isItalic, isCloseButtonVisible, Color.decode(colorCode), iconString, fontSize);
            currentSubTabsContainerHandler.updateByTabFeaturesObjectStyle(tabFeaturesObjectStyle, true);
            sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler);
        });
        return profile;
    }

    private static JMenuItem predefinedStyleMenuWithNoFontChange(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler, String text, boolean isCloseButtonVisible, String colorCode, String iconString) {
        return predefinedStyleMenu(sharedParameters, currentSubTabsContainerHandler, text, currentSubTabsContainerHandler.getFontName(), (int) currentSubTabsContainerHandler.getFontSize(), currentSubTabsContainerHandler.isBold(), currentSubTabsContainerHandler.isItalic(), isCloseButtonVisible, colorCode, iconString);
    }

    public static boolean changeToolTabbedPaneUI_safe(SharpenerSharedParameters sharedParameters, BurpUITools.MainTabs currentToolTab, boolean shouldOriginalBeSet, int counter) {
        boolean result = true;
        try {
            // should have already been loaded but just in case something has changed
            // hopefully it has not been tainted already!
            var currentToolTabbedPane = sharedParameters.get_toolTabbedPane(currentToolTab);
            if(currentToolTabbedPane == null){
                sharedParameters.printDebugMessage("Error in getting the current tool tabs: " + currentToolTab);
                return false;
            }

            if (sharedParameters.originalSubTabbedPaneUI.get(currentToolTab) == null) {
                sharedParameters.originalSubTabbedPaneUI.put(currentToolTab,
                        currentToolTabbedPane.getUI());
            }

            boolean isMinimizeTabSize = sharedParameters.preferences.safeGetBooleanSetting("minimizeSize_" + currentToolTab);
            boolean isFixedTabPosition = (sharedParameters.preferences.safeGetBooleanSetting("isTabFixedPosition_" + currentToolTab));
            boolean isFiltered = sharedParameters.isFiltered(currentToolTab);

            boolean isOriginal = shouldOriginalBeSet && !isMinimizeTabSize && !isFiltered &&
                    (isFixedTabPosition || (!(sharedParameters.burpMajorVersion > 2022) && (sharedParameters.burpMajorVersion != 2022 || !(sharedParameters.burpMinorVersion >= 3)))) &&
                    (!isFixedTabPosition || (!(sharedParameters.burpMajorVersion < 2022) && (sharedParameters.burpMajorVersion != 2022 || !(sharedParameters.burpMinorVersion < 3))));


            if (isOriginal || sharedParameters.isTabGroupSupportedByDefault) {
                currentToolTabbedPane.updateUI();
            } else {
                currentToolTabbedPane.setUI(SubTabsCustomTabbedPaneUI.getUI(sharedParameters, currentToolTab));
            }

            currentToolTabbedPane.revalidate();
            currentToolTabbedPane.repaint();
            new java.util.Timer().schedule(
                    new java.util.TimerTask() {
                        @Override
                        public void run() {
                            sharedParameters.allSettings.subTabsSettings.updateSubTabsUI(currentToolTab);
                        }
                    },
                    3000 // 3 seconds-delay to ensure all has been settled!
            );
        } catch (Exception e) {
            result = false;
        }

        return result;
    }


    public static void changeToolTabbedPaneUI_safe(SharpenerSharedParameters sharedParameters, BurpUITools.MainTabs currentToolTab, boolean shouldOriginalBeSet) {
        SwingUtilities.invokeLater(() -> {
            // sometimes we have errors when using SetUI - we use this error catching and delay mechanism to hopefully overcome this!
            int counter = 0;
            boolean isSuccessful = false;
            while (counter < 3 && !isSuccessful) {
                sharedParameters.printDebugMessage("Try number " + counter + " to update the UI");
                if (!isSuccessful) {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
                isSuccessful = changeToolTabbedPaneUI_safe(sharedParameters, currentToolTab, shouldOriginalBeSet, counter);
                counter++;
            }
        });
    }

    public static void changeToolTabbedPaneUI_safe(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler, boolean shouldOriginalBeSet) {
        SwingUtilities.invokeLater(() -> {
            // sometimes we have errors when using SetUI - we use this error catching and delay mechanism to hopefully overcome this!
            int counter = 0;
            boolean isSuccessful = false;
            while (counter < 3 && !isSuccessful) {
                sharedParameters.printDebugMessage("Try number " + counter + " to update the UI");
                if (!isSuccessful) {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
                isSuccessful = changeToolTabbedPaneUI_safe(sharedParameters, currentSubTabsContainerHandler.currentToolTab, shouldOriginalBeSet, counter);
                counter++;
            }

        });
    }

    public static void setTabTitleFilter(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler) {
        if (currentSubTabsContainerHandler == null)
            return;

        // filterOperationMode -->
        //operationMode=0 -> use RegEx
        //operationMode=1 -> Custom style only
        //operationMode=2 -> Custom style or not numerical
        //operationMode=3 -> Websocket tabs

        if (!sharedParameters.titleFilterRegEx.isBlank() || sharedParameters.filterOperationMode.get(currentSubTabsContainerHandler.currentToolTab) > 0) {
            for (SubTabsContainerHandler subTabsContainerHandlerItem : sharedParameters.allSubTabContainerHandlers.get(currentSubTabsContainerHandler.currentToolTab)) {
                String subTabTitle = subTabsContainerHandlerItem.getTabTitle();

                // if it is not negative (default), then if we have a match, we have a winner so default is false and vice versa
                // the exception is for mode 2, as if we have a match for numbers then we don't like it!
                boolean interestingItemUsingRegEx = sharedParameters.isTitleFilterNegative;

                if (!sharedParameters.titleFilterRegEx.isBlank()) {
                    // RegEx Matched
                    interestingItemUsingRegEx = Pattern.compile(sharedParameters.titleFilterRegEx, Pattern.CASE_INSENSITIVE).matcher(subTabTitle).find();
                }

                if (sharedParameters.filterOperationMode.get(currentSubTabsContainerHandler.currentToolTab) == 2) {
                    //  in Custom style or not numerical, we need to exclude all numbers as RegEx has been set to number only, we need to make it negative again!
                    interestingItemUsingRegEx = !interestingItemUsingRegEx;
                }

                if (sharedParameters.isTitleFilterNegative) {
                    // in negative state, anything positive will be negative at this point!
                    interestingItemUsingRegEx = !interestingItemUsingRegEx;
                }

                boolean interestingItemUsingStyle = sharedParameters.isTitleFilterNegative;
                if ((sharedParameters.filterOperationMode.get(currentSubTabsContainerHandler.currentToolTab) == 1 ||
                        sharedParameters.filterOperationMode.get(currentSubTabsContainerHandler.currentToolTab) == 2)) {
                    // Checking Custom style only when we do not think it is an interesting item by this point
                    interestingItemUsingStyle = !subTabsContainerHandlerItem.isDefault();

                    if (sharedParameters.isTitleFilterNegative) {
                        // in negative state, anything positive will be negative at this point!
                        interestingItemUsingStyle = !interestingItemUsingStyle;
                    }
                }

                boolean isItFinallyInteresting = false;
                if (sharedParameters.filterOperationMode.get(currentSubTabsContainerHandler.currentToolTab) == 2) {
                    // mode 2
                    isItFinallyInteresting = interestingItemUsingStyle || interestingItemUsingRegEx;
                } else if (sharedParameters.filterOperationMode.get(currentSubTabsContainerHandler.currentToolTab) == 1) {
                    // mode 1
                    isItFinallyInteresting = interestingItemUsingStyle;
                } else if (sharedParameters.filterOperationMode.get(currentSubTabsContainerHandler.currentToolTab) == 0) {
                    // mode 0
                    isItFinallyInteresting = interestingItemUsingRegEx;
                } else if (sharedParameters.filterOperationMode.get(currentSubTabsContainerHandler.currentToolTab) == 3) {
                    // mode 3
                    isItFinallyInteresting = subTabsContainerHandlerItem.isWebSocketTab() ^ sharedParameters.isTitleFilterNegative;
                }

                // if it is not an interesting item, we need to hide it!
                subTabsContainerHandlerItem.setVisible(isItFinallyInteresting);
            }

            // now we need to change the UI, so it will return 0 for width of the filtered tabs
            changingTabbedPaneUiToHideTabs(sharedParameters, currentSubTabsContainerHandler);
        }
    }

    private static void changingTabbedPaneUiToHideTabs(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler) {
        if (currentSubTabsContainerHandler == null)
            return;

        var currentToolTabbedPane = sharedParameters.get_toolTabbedPane(currentSubTabsContainerHandler.currentToolTab);
        if(currentToolTabbedPane == null)
            return;

        if (sharedParameters.isFiltered(currentSubTabsContainerHandler.currentToolTab)) {
            sharedParameters.printDebugMessage("Changing UI so it can hide tabs");
            if (sharedParameters.originalSubTabbedPaneUI.get(currentSubTabsContainerHandler.currentToolTab) == null)
                sharedParameters.originalSubTabbedPaneUI.put(currentSubTabsContainerHandler.currentToolTab,
                        currentToolTabbedPane.getUI());

            changeToolTabbedPaneUI_safe(sharedParameters, currentSubTabsContainerHandler, false);
        } else {
            changeToolTabbedPaneUI_safe(sharedParameters, currentSubTabsContainerHandler, true);
            sharedParameters.printDebugMessage("Removing the filter");
        }
    }

    public static void showAllTabTitles(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler) {
        if (currentSubTabsContainerHandler == null)
            return;

        if (sharedParameters.isFiltered(currentSubTabsContainerHandler.currentToolTab)) {
            for (SubTabsContainerHandler subTabsContainerHandlerItem : sharedParameters.allSubTabContainerHandlers.get(currentSubTabsContainerHandler.currentToolTab)) {
                subTabsContainerHandlerItem.setVisible(true);
            }
            changeToolTabbedPaneUI_safe(sharedParameters, currentSubTabsContainerHandler, true);
        }
    }

    public static void toggleCurrentTabVisibility(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler) {
        if (currentSubTabsContainerHandler == null)
            return;

        var currentToolTabbedPane = sharedParameters.get_toolTabbedPane(currentSubTabsContainerHandler.currentToolTab);
        if(currentToolTabbedPane == null)
            return;

        currentSubTabsContainerHandler.setVisible(!currentSubTabsContainerHandler.getVisible());

        currentToolTabbedPane.revalidate();
        currentToolTabbedPane.repaint();
        new java.util.Timer().schedule(
                new java.util.TimerTask() {
                    @Override
                    public void run() {
                        sharedParameters.allSettings.subTabsSettings.updateSubTabsUI(currentSubTabsContainerHandler.currentToolTab);
                    }
                },
                2000 // 2 seconds-delay to ensure all has been settled!
        );

        // now we need to change the UI, so it will return 0 for width of the filtered tabs
        changingTabbedPaneUiToHideTabs(sharedParameters, currentSubTabsContainerHandler);
    }

    public static SubTabsContainerHandler getSubTabContainerHandlerFromEvent(SharpenerSharedParameters sharedParameters, AWTEvent event) {
        SubTabsContainerHandler subTabsContainerHandler = null;
        if (event.getSource() instanceof Component) {
            JTabbedPane tabbedPane = (JTabbedPane) UIWalker.FindUIObjectInParentComponents((Component) event.getSource(), 4, new UiSpecObject(JTabbedPane.class));
            if (tabbedPane != null) {
                int currentSelection = tabbedPane.getSelectedIndex();
                subTabsContainerHandler = getSubTabContainerHandlerFromSharedParameters(sharedParameters, tabbedPane, currentSelection);
            }
        }
        return subTabsContainerHandler;
    }

    public static SubTabsContainerHandler getSubTabContainerHandlerFromSharedParameters(SharpenerSharedParameters sharedParameters, JTabbedPane tabbedPane, int currentIndex) {
        SubTabsContainerHandler subTabsContainerHandler = null;

        SubTabsContainerHandler tempSubTabsContainerHandler = new SubTabsContainerHandler(sharedParameters, tabbedPane, currentIndex, true);
        BurpUITools.MainTabs currentToolTab = tempSubTabsContainerHandler.currentToolTab;

        ArrayList<SubTabsContainerHandler> subTabsContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentToolTab);

        if (subTabsContainerHandlers != null) {
            int sharedParamIndex = subTabsContainerHandlers.indexOf(tempSubTabsContainerHandler);
            if (sharedParamIndex >= 0)
                subTabsContainerHandler = subTabsContainerHandlers.get(sharedParamIndex);
        }


        return subTabsContainerHandler;
    }

    public static void showPopupMenu(SharpenerSharedParameters sharedParameters, AWTEvent event) {
        showPopupMenu(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event), null);
    }

    public static void showPopupMenu(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler, AWTEvent event) {
        if (currentSubTabsContainerHandler == null)
            return;

        var currentToolTabbedPane = sharedParameters.get_toolTabbedPane(currentSubTabsContainerHandler.currentToolTab);
        if(currentToolTabbedPane == null)
            return;

        // creating popup menu
        JPopupMenu popupMenu = createPopupMenu(sharedParameters, currentSubTabsContainerHandler);
        int x;
        int y;
        if (currentToolTabbedPane.getTabLayoutPolicy() == JTabbedPane.SCROLL_TAB_LAYOUT && event instanceof MouseEvent) {
            x = ((MouseEvent) event).getX();
            y = ((MouseEvent) event).getY() + currentToolTabbedPane.getTabComponentAt(currentSubTabsContainerHandler.getTabIndex()).getHeight() / 2;
        } else {
            x = currentToolTabbedPane.getTabComponentAt(currentSubTabsContainerHandler.getTabIndex()).getX();
            y = currentToolTabbedPane.getTabComponentAt(currentSubTabsContainerHandler.getTabIndex()).getY() + currentToolTabbedPane.getTabComponentAt(currentSubTabsContainerHandler.getTabIndex()).getHeight();
        }
        // showing popup menu
        popupMenu.show(currentToolTabbedPane, x, y);
    }

    public static void defineRegExPopupForSearchAndJump(SharpenerSharedParameters sharedParameters, AWTEvent event) {
        defineRegExPopupForSearchAndJump(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event));
    }

    public static void defineRegExPopupForSearchAndJump(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler) {
        if(currentSubTabsContainerHandler != null)
            defineRegExPopupForSearchAndJump(sharedParameters, currentSubTabsContainerHandler.currentToolTab);
    }

    public static void defineRegExPopupForSearchAndJump(SharpenerSharedParameters sharedParameters, BurpUITools.MainTabs currentToolTab) {
        String titleKeyword = UIHelper.showPlainInputMessage("Enter a Regular Expression:", "Search in titles and jump to tab", sharedParameters.searchedTabTitleForJumpToTab, sharedParameters.get_mainFrameUsingMontoya());
        if (!titleKeyword.isEmpty()) {
            boolean result = false;
            if (Utilities.isValidRegExPattern(titleKeyword)) {
                sharedParameters.searchedTabTitleForJumpToTab = titleKeyword;
                ArrayList<SubTabsContainerHandler> subTabsContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentToolTab);
                for (SubTabsContainerHandler subTabsContainerHandlerItem : subTabsContainerHandlers) {
                    if (subTabsContainerHandlerItem.getVisible()) {
                        String subTabTitle = subTabsContainerHandlerItem.getTabTitle();
                        if (Pattern.compile(titleKeyword, Pattern.CASE_INSENSITIVE).matcher(subTabTitle).find()) {
                            jumpToTabIndex(sharedParameters, subTabsContainerHandlerItem, subTabsContainerHandlerItem.getTabIndex());
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
                UIHelper.showWarningMessage("Regular expression was invalid.", sharedParameters.get_mainFrameUsingMontoya());
                sharedParameters.printlnError("invalid regex: " + titleKeyword);
            }
        }
    }

    public static void searchInTabTitlesAndJump(SharpenerSharedParameters sharedParameters, AWTEvent event, boolean isNext) {
        searchInTabTitlesAndJump(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event), null, isNext);
    }

    public static void searchInTabTitlesAndJump(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler, JMenuItem notificationMenuItem, boolean isNext) {
        if (!sharedParameters.searchedTabTitleForJumpToTab.isEmpty() && currentSubTabsContainerHandler != null) {
            boolean result = false;
            ArrayList<SubTabsContainerHandler> subTabsContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentSubTabsContainerHandler.currentToolTab);
            ArrayList<SubTabsContainerHandler> tempSubTabsContainerHandlers;
            if (isNext) {
                tempSubTabsContainerHandlers = new ArrayList<>(subTabsContainerHandlers.subList(currentSubTabsContainerHandler.parentTabbedPane.getSelectedIndex(), subTabsContainerHandlers.size()));
            } else {
                tempSubTabsContainerHandlers = new ArrayList<>(subTabsContainerHandlers.subList(0, currentSubTabsContainerHandler.parentTabbedPane.getSelectedIndex()));
                Collections.reverse(tempSubTabsContainerHandlers);
            }

            for (SubTabsContainerHandler subTabsContainerHandlerItem : tempSubTabsContainerHandlers) {
                if ((subTabsContainerHandlerItem.getTabIndex() > subTabsContainerHandlerItem.parentTabbedPane.getSelectedIndex() && isNext)
                        || (subTabsContainerHandlerItem.getTabIndex() < subTabsContainerHandlerItem.parentTabbedPane.getSelectedIndex() && !isNext)) {
                    if (subTabsContainerHandlerItem.getVisible()) {
                        String subTabTitle = subTabsContainerHandlerItem.getTabTitle();
                        if (Pattern.compile(sharedParameters.searchedTabTitleForJumpToTab, Pattern.CASE_INSENSITIVE).matcher(subTabTitle).find()) {
                            jumpToTabIndex(sharedParameters, subTabsContainerHandlerItem, subTabsContainerHandlerItem.getTabIndex());
                            // This is because when we use mouse action, the menu won't be closed
                            if (notificationMenuItem != null)
                                setNotificationMenuMessage(sharedParameters, currentSubTabsContainerHandler, notificationMenuItem, "Tab Title: " + currentSubTabsContainerHandler.parentTabbedPane.getTitleAt(currentSubTabsContainerHandler.parentTabbedPane.getSelectedIndex()).trim());
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

    public static void jumpToFirstTab(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler) {
        jumpToTabIndex(sharedParameters, currentSubTabsContainerHandler, 0);
        sharedParameters.printDebugMessage("Jump to first tab");
    }

    public static void jumpToLastTab(SharpenerSharedParameters sharedParameters, ActionEvent event) {
        jumpToLastTab(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event));
    }

    public static void jumpToLastTab(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler) {
        if (currentSubTabsContainerHandler == null)
            return;

        int maxIndex = currentSubTabsContainerHandler.parentTabbedPane.getTabCount() - 2;

        if (sharedParameters.isTabGroupSupportedByDefault)
            maxIndex += 1;

        jumpToTabIndex(sharedParameters, currentSubTabsContainerHandler, maxIndex);
        sharedParameters.printDebugMessage("Jump to last tab");
    }

    public static void jumpToPreviousTab(SharpenerSharedParameters sharedParameters, ActionEvent event) {
        jumpToPreviousTab(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event), null);
    }

    public static void jumpToPreviousTab(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler, JMenuItem notificationMenuItem) {
        if (currentSubTabsContainerHandler == null)
            return;
        if (currentSubTabsContainerHandler.parentTabbedPane.getSelectedIndex() > 0) {
            int chosenOne = currentSubTabsContainerHandler.parentTabbedPane.getSelectedIndex() - 1;

            SubTabsContainerHandler chosenOneSubTabsContainerHandler = getSubTabContainerHandlerFromSharedParameters(sharedParameters, currentSubTabsContainerHandler.parentTabbedPane, chosenOne);

            while (chosenOneSubTabsContainerHandler == null || !currentSubTabsContainerHandler.parentTabbedPane.isEnabledAt(chosenOne)
                    || !chosenOneSubTabsContainerHandler.isValid() || chosenOneSubTabsContainerHandler.isGroupContainerTab()
                    || !chosenOneSubTabsContainerHandler.isTitleVisible()) {
                chosenOne--;
                int maxIndex = currentSubTabsContainerHandler.parentTabbedPane.getTabCount();
                if (sharedParameters.isTabGroupSupportedByDefault)
                    maxIndex += 1;

                if (chosenOne < 0 || chosenOne >= maxIndex) {
                    chosenOne = currentSubTabsContainerHandler.parentTabbedPane.getSelectedIndex();
                    break;
                }
                chosenOneSubTabsContainerHandler = getSubTabContainerHandlerFromSharedParameters(sharedParameters, currentSubTabsContainerHandler.parentTabbedPane, chosenOne);
            }
            jumpToTabIndex(sharedParameters, currentSubTabsContainerHandler, chosenOne);
            // This is because when we use mouse action, the menu won't be closed
            if (notificationMenuItem != null)
                setNotificationMenuMessage(sharedParameters, currentSubTabsContainerHandler, notificationMenuItem, "Tab Title: " + currentSubTabsContainerHandler.parentTabbedPane.getTitleAt(currentSubTabsContainerHandler.parentTabbedPane.getSelectedIndex()).trim());

            sharedParameters.printDebugMessage("Jump to previous tab");
        }
    }

    public static void jumpToNextTab(SharpenerSharedParameters sharedParameters, ActionEvent event) {
        jumpToNextTab(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event), null);
    }

    public static void jumpToNextTab(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler, JMenuItem notificationMenuItem) {
        if (currentSubTabsContainerHandler == null)
            return;
        int maxIndex = currentSubTabsContainerHandler.parentTabbedPane.getTabCount() - 2;

        if (sharedParameters.isTabGroupSupportedByDefault)
            maxIndex += 1;

        if (currentSubTabsContainerHandler.parentTabbedPane.getSelectedIndex() < maxIndex) {
            int chosenOne = currentSubTabsContainerHandler.parentTabbedPane.getSelectedIndex() + 1;
            SubTabsContainerHandler chosenOneSubTabsContainerHandler = getSubTabContainerHandlerFromSharedParameters(sharedParameters, currentSubTabsContainerHandler.parentTabbedPane, chosenOne);

            while (chosenOneSubTabsContainerHandler == null || !currentSubTabsContainerHandler.parentTabbedPane.isEnabledAt(chosenOne)
                    || !chosenOneSubTabsContainerHandler.isValid() || chosenOneSubTabsContainerHandler.isGroupContainerTab()
                    || !chosenOneSubTabsContainerHandler.isTitleVisible()) {
                chosenOne++;
                int maxIndex2 = currentSubTabsContainerHandler.parentTabbedPane.getTabCount();
                if (sharedParameters.isTabGroupSupportedByDefault)
                    maxIndex2 += 1;
                if (chosenOne < 0 || chosenOne >= maxIndex2) {
                    chosenOne = currentSubTabsContainerHandler.parentTabbedPane.getSelectedIndex();
                    break;
                }
                chosenOneSubTabsContainerHandler = getSubTabContainerHandlerFromSharedParameters(sharedParameters, currentSubTabsContainerHandler.parentTabbedPane, chosenOne);
            }

            jumpToTabIndex(sharedParameters, currentSubTabsContainerHandler, chosenOne);
            // This is because when we use mouse action, the menu won't be closed
            if (notificationMenuItem != null)
                setNotificationMenuMessage(sharedParameters, currentSubTabsContainerHandler, notificationMenuItem, "Tab Title: " + currentSubTabsContainerHandler.parentTabbedPane.getTitleAt(currentSubTabsContainerHandler.parentTabbedPane.getSelectedIndex()).trim());

            sharedParameters.printDebugMessage("Jump to next tab");
        }
    }

    public static void jumpToPreviouslySelectedTab(SharpenerSharedParameters sharedParameters, ActionEvent event) {
        jumpToPreviouslySelectedTab(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event), null);
    }

    public static void jumpToPreviouslySelectedTab(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler, JMenuItem notificationMenuItem) {
        if (currentSubTabsContainerHandler == null)
            return;

        Integer previouslySelectedIndex = null;
        Integer currentSelectedIndex = sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabsContainerHandler.currentToolTab).pollLast();

        if (!currentSubTabsContainerHandler.isDotDotDotTab()) {
            previouslySelectedIndex = sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabsContainerHandler.currentToolTab).pollLast();
        }

        if (previouslySelectedIndex != null && currentSubTabsContainerHandler.parentTabbedPane.getTabComponentAt(previouslySelectedIndex) != null) {
            fixHistoryAndJumpToTabIndex(sharedParameters, currentSubTabsContainerHandler, previouslySelectedIndex, false, false, true);
            sharedParameters.printDebugMessage("Jump to previously selected tab");
        } else {
            sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabsContainerHandler.currentToolTab).add(currentSelectedIndex);
            sharedParameters.printDebugMessage("No previously selected tab was found");
        }

        if (notificationMenuItem != null)
            setNotificationMenuMessage(sharedParameters, currentSubTabsContainerHandler, notificationMenuItem, "Tab Title: " + currentSubTabsContainerHandler.parentTabbedPane.getTitleAt(currentSubTabsContainerHandler.parentTabbedPane.getSelectedIndex()).trim());


    }

    public static void jumpToNextlySelectedTab(SharpenerSharedParameters sharedParameters, ActionEvent event) {
        jumpToNextlySelectedTab(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event), null);
    }

    public static void jumpToNextlySelectedTab(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler, JMenuItem notificationMenuItem) {
        if (currentSubTabsContainerHandler == null)
            return;

        Integer nextlySelectedIndex;
        nextlySelectedIndex = sharedParameters.subTabNextlySelectedIndexHistory.get(currentSubTabsContainerHandler.currentToolTab).pollLast();

        if (nextlySelectedIndex != null && currentSubTabsContainerHandler.parentTabbedPane.getTabComponentAt(nextlySelectedIndex) != null) {
            fixHistoryAndJumpToTabIndex(sharedParameters, currentSubTabsContainerHandler, nextlySelectedIndex, false, true, true);
        }

        if (notificationMenuItem != null)
            setNotificationMenuMessage(sharedParameters, currentSubTabsContainerHandler, notificationMenuItem, "Tab Title: " + currentSubTabsContainerHandler.parentTabbedPane.getTitleAt(currentSubTabsContainerHandler.parentTabbedPane.getSelectedIndex()).trim());

        sharedParameters.printDebugMessage("Jump to previously selected tab");
    }

    public static void jumpToTabIndex(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler, int indexNumber) {
        fixHistoryAndJumpToTabIndex(sharedParameters, currentSubTabsContainerHandler, indexNumber, true, true, true);
    }

    public static void fixHistoryAndJumpToTabIndex(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler, int indexNumber, boolean cleanNextlySelectedTabs, boolean ignoreNextlySelectedTabs, boolean shouldJump) {
        if (currentSubTabsContainerHandler == null)
            return;

        if (currentSubTabsContainerHandler.parentTabbedPane.getTabComponentAt(indexNumber) != null) {
            if (cleanNextlySelectedTabs) {
                sharedParameters.subTabNextlySelectedIndexHistory.get(currentSubTabsContainerHandler.currentToolTab).clear();
            } else {
                if (!ignoreNextlySelectedTabs &&
                        (sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabsContainerHandler.currentToolTab).size() <= 0 ||
                                (sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabsContainerHandler.currentToolTab).size() > 0 &&
                                        sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabsContainerHandler.currentToolTab).getLast() != currentSubTabsContainerHandler.getTabIndex()))
                ) {
                    sharedParameters.subTabNextlySelectedIndexHistory.get(currentSubTabsContainerHandler.currentToolTab).add(currentSubTabsContainerHandler.getTabIndex());
                }

            }

            if (
                    sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabsContainerHandler.currentToolTab).size() <= 0
                    ||
                    (
                        sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabsContainerHandler.currentToolTab).getLast() != indexNumber
                        &&
                        (
                                currentSubTabsContainerHandler.parentTabbedPane.getTabCount() - 1 != indexNumber || sharedParameters.isTabGroupSupportedByDefault
                        )
                    )
                )
            {
                sharedParameters.subTabPreviouslySelectedIndexHistory.get(currentSubTabsContainerHandler.currentToolTab).add(indexNumber);
            }
            if(shouldJump)
                currentSubTabsContainerHandler.parentTabbedPane.setSelectedIndex(indexNumber);
        }
    }

    public static void copyTitle(SharpenerSharedParameters sharedParameters, ActionEvent event) {
        copyTitle(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event));
    }

    public static void copyTitle(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler) {
        if (currentSubTabsContainerHandler == null)
            return;

        String tabTitle = currentSubTabsContainerHandler.getTabTitle();
        // copying to clipboard as well
        Toolkit.getDefaultToolkit()
                .getSystemClipboard()
                .setContents(
                        new StringSelection(tabTitle),
                        null
                );
        sharedParameters.printDebugMessage("Title has been copied to clipboard");
    }
    public static void pasteTitle(SharpenerSharedParameters sharedParameters, ActionEvent event) {
        pasteTitle(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event));
    }

    public static void pasteTitle(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler) {
        try {
            if (currentSubTabsContainerHandler == null)
                return;

            String clipboardText = (String) Toolkit.getDefaultToolkit()
                    .getSystemClipboard().getData(DataFlavor.stringFlavor);
            sharedParameters.lastClipboardText = clipboardText.trim().replaceAll("^#\\d+\\s+", "");
        } catch (Exception e) {
            sharedParameters.lastClipboardText = "";
        }

        if (!sharedParameters.lastClipboardText.isBlank()) {
            currentSubTabsContainerHandler.setTabTitle(sharedParameters.lastClipboardText, true);
            sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler);
            sharedParameters.printDebugMessage("Title has been pasted");
        }
    }

    public static void renameTitle(SharpenerSharedParameters sharedParameters, ActionEvent event) {
        renameTitle(sharedParameters, getSubTabContainerHandlerFromEvent(sharedParameters, event));
    }

    public static void renameTitle(SharpenerSharedParameters sharedParameters, SubTabsContainerHandler currentSubTabsContainerHandler) {
        if (currentSubTabsContainerHandler == null)
            return;

        String newTitle = UIHelper.showPlainInputMessage("Edit the Title", "Rename Title", currentSubTabsContainerHandler.getTabTitle(), sharedParameters.get_mainFrameUsingMontoya());
        if (!newTitle.isEmpty() && !newTitle.equals(currentSubTabsContainerHandler.getTabTitle())) {
            currentSubTabsContainerHandler.setTabTitle(newTitle, true);
            sharedParameters.allSettings.subTabsSettings.saveSettings(currentSubTabsContainerHandler);
            sharedParameters.printDebugMessage("Title renamed...");
        }
    }
}
