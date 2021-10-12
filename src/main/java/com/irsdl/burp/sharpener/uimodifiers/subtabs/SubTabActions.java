// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.uimodifiers.subtabs;

import com.irsdl.burp.generic.BurpUITools;
import com.irsdl.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.burp.sharpener.objects.TabFeaturesObjectStyle;
import com.irsdl.generic.ImageHelper;
import com.irsdl.generic.JScrollMenu;
import com.irsdl.generic.UIHelper;
import com.irsdl.generic.Utilities;

import javax.imageio.ImageIO;
import javax.swing.*;
import javax.swing.colorchooser.AbstractColorChooserPanel;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.regex.Pattern;

public class SubTabActions {
    public static void tabClicked(final MouseEvent e, SharpenerSharedParameters sharedParameters) {
        if (SwingUtilities.isMiddleMouseButton(e) || e.isAltDown() || ((e.getModifiers() & ActionEvent.ALT_MASK) == ActionEvent.ALT_MASK)) {
            if (e.getComponent() instanceof JTabbedPane) {
                JTabbedPane tabbedPane = (JTabbedPane) e.getComponent();
                int tabIndex;
                /*
                // this was useful when we did not know which tab has been selected but in Burp Suite a tab will be selected upon a click so we can find the index that way
                int tabIndex = tabbedPane.getUI().tabForCoordinate(tabbedPane, e.getX(), e.getY());
                if (tabIndex < 0 || tabIndex > tabbedPane.getTabCount() - 1) return;
                */

                tabIndex = tabbedPane.getSelectedIndex();

                SubTabContainerHandler subTabContainerHandler = new SubTabContainerHandler(sharedParameters, tabbedPane, tabIndex);

                if (!subTabContainerHandler.isValid()) return;

                boolean isCTRL_Key = (e.getModifiers() & ActionEvent.CTRL_MASK) == ActionEvent.CTRL_MASK || e.isControlDown();
                // Middle key is like the Alt key!
                //boolean isALT_Key = (e.getModifiers() & ActionEvent.ALT_MASK) == ActionEvent.ALT_MASK;
                boolean isSHIFT_Key = (e.getModifiers() & ActionEvent.SHIFT_MASK) == ActionEvent.SHIFT_MASK || e.isShiftDown();

                int maxSize = 40;
                int minSize = 10;
                if (!isCTRL_Key && !isSHIFT_Key) {
                    JPopupMenu popupMenu = createPopupMenu(sharedParameters, subTabContainerHandler);
                    //popupMenu.show(tabbedPane, e.getX(), e.getY());
                    int x;
                    int y;
                    if (tabbedPane.getTabLayoutPolicy() == JTabbedPane.SCROLL_TAB_LAYOUT) {
                        x = e.getX();
                        y = e.getY() + tabbedPane.getTabComponentAt(tabIndex).getHeight() / 2;
                    } else {
                        x = tabbedPane.getTabComponentAt(tabIndex).getX();
                        y = tabbedPane.getTabComponentAt(tabIndex).getY() + tabbedPane.getTabComponentAt(tabIndex).getHeight();
                    }
                    popupMenu.show(tabbedPane, x, y);
                } else if (isCTRL_Key && !isSHIFT_Key) {
                    // Make it bigger and bold when middle click + ctrl
                    if (subTabContainerHandler.getFontSize() < maxSize) {
                        if (!subTabContainerHandler.isBold())
                            subTabContainerHandler.toggleBold();
                        subTabContainerHandler.setFontSize(subTabContainerHandler.getFontSize() + 2);
                        subTabContainerHandler.hideCloseButton();
                    }
                } else if (isCTRL_Key && isSHIFT_Key) {
                    // Make it smaller but bold when middle click + ctrl + shift
                    if (subTabContainerHandler.getFontSize() > minSize) {
                        if (!subTabContainerHandler.isBold())
                            subTabContainerHandler.toggleBold();
                        subTabContainerHandler.setFontSize(subTabContainerHandler.getFontSize() - 2);
                        subTabContainerHandler.hideCloseButton();
                    }
                } else if (!isCTRL_Key && isSHIFT_Key) {
                    // middle click with shift: should make it red and big and bold
                    TabFeaturesObjectStyle tabFeaturesObjectStyle = new TabFeaturesObjectStyle("High: Red, Big, and Bold", "Arial", 18, true, false, false, Color.decode("#f71414"));
                    subTabContainerHandler.updateByTabFeaturesObjectStyle(tabFeaturesObjectStyle);
                }

                if (subTabContainerHandler.hasChanged) {
                    sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(subTabContainerHandler);
                    subTabContainerHandler.hasChanged = false;
                }
            }
        }
    }


    private static JPopupMenu createPopupMenu(SharpenerSharedParameters sharedParameters, SubTabContainerHandler currentSubTabContainerHandler) {
        JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem menuItem = new JMenuItem("Tab Title: " + currentSubTabContainerHandler.getTabTitle());
        menuItem.setEnabled(false);
        popupMenu.add(menuItem);
        popupMenu.addSeparator();

        JMenuItem pasteStyleMenu = new JMenuItem("Paste Style");
        if (sharedParameters.copiedTabFeaturesObjectStyle == null) {
            pasteStyleMenu.setEnabled(false);
        }
        pasteStyleMenu.addActionListener(e -> {
            if (sharedParameters.copiedTabFeaturesObjectStyle != null) {
                currentSubTabContainerHandler.updateByTabFeaturesObjectStyle(sharedParameters.copiedTabFeaturesObjectStyle);
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
                sharedParameters.printDebugMessages("Style pasted...");
            }
        });
        popupMenu.add(pasteStyleMenu);

        JMenuItem copyStyleMenu = new JMenuItem("Copy Style");
        //if (currentSubTabContainerHandler.isDefault())
        //    copyStyleMenu.setEnabled(false);
        copyStyleMenu.addActionListener(e -> {
            sharedParameters.copiedTabFeaturesObjectStyle = currentSubTabContainerHandler.getTabFeaturesObjectStyle();
            sharedParameters.printDebugMessages("Style copied...");
        });
        popupMenu.add(copyStyleMenu);


        JCheckBoxMenuItem defaultProfile = new JCheckBoxMenuItem("Reset to Default");
        defaultProfile.addActionListener(e -> {
            currentSubTabContainerHandler.setToDefault();
            sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
        });
        if (currentSubTabContainerHandler.isDefault())
            defaultProfile.setEnabled(false);
        popupMenu.add(defaultProfile);

        JMenu profileMenu = new JMenu("Predefined Patterns");

        JCheckBoxMenuItem highProfile = new JCheckBoxMenuItem("High: Red, Big, and Bold");
        highProfile.addActionListener(e -> {
            TabFeaturesObjectStyle tabFeaturesObjectStyle = new TabFeaturesObjectStyle("High: Red, Big, and Bold", "Arial", 18, true, false, false, Color.decode("#f71414"));
            currentSubTabContainerHandler.updateByTabFeaturesObjectStyle(tabFeaturesObjectStyle);
            sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
        });
        profileMenu.add(highProfile);

        JCheckBoxMenuItem mediumProfile = new JCheckBoxMenuItem("Medium: Orange, Big, and Bold");
        mediumProfile.addActionListener(e -> {
            TabFeaturesObjectStyle tabFeaturesObjectStyle = new TabFeaturesObjectStyle("Medium: Orange, Big, and Bold", "Arial", 18, true, false, false, Color.decode("#ff7e0d"));
            currentSubTabContainerHandler.updateByTabFeaturesObjectStyle(tabFeaturesObjectStyle);
            sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
        });
        profileMenu.add(mediumProfile);

        JCheckBoxMenuItem lowProfile = new JCheckBoxMenuItem("Low: Yellow, Bold");
        lowProfile.addActionListener(e -> {
            TabFeaturesObjectStyle tabFeaturesObjectStyle = new TabFeaturesObjectStyle("Low: Yellow, Bold", "Arial", 14, true, false, false, Color.decode("#fadc00"));
            currentSubTabContainerHandler.updateByTabFeaturesObjectStyle(tabFeaturesObjectStyle);
            sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
        });
        profileMenu.add(lowProfile);

        JCheckBoxMenuItem infoProfile = new JCheckBoxMenuItem("Info: Green, Bold, Italic");
        infoProfile.addActionListener(e -> {
            TabFeaturesObjectStyle tabFeaturesObjectStyle = new TabFeaturesObjectStyle("Info: Green, Bold, Italic", "Arial", 14, true, true, false, Color.decode("#0d9e1e"));
            currentSubTabContainerHandler.updateByTabFeaturesObjectStyle(tabFeaturesObjectStyle);
            sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
        });
        profileMenu.add(infoProfile);

        popupMenu.add(profileMenu);

        JMenu customStyleMenu = new JMenu("Custom Style");
        JCheckBoxMenuItem closeButtonMenuItem = new JCheckBoxMenuItem("Remove Close Button");
        closeButtonMenuItem.addActionListener(e -> {
            currentSubTabContainerHandler.setVisibleCloseButton(!closeButtonMenuItem.isSelected());
            sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
        });
        closeButtonMenuItem.setSelected(!currentSubTabContainerHandler.getVisibleCloseButton());
        customStyleMenu.add(closeButtonMenuItem);

        JMenu fontNameMenu = new JScrollMenu("Font Name");
        String[] fonts = GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames();

        for (int i = 0; i < fonts.length; i++) {
            JCheckBoxMenuItem fontnameItem = new JCheckBoxMenuItem(fonts[i]);
            fontnameItem.setSelected(fonts[i].equalsIgnoreCase(currentSubTabContainerHandler.getFontName()));
            String finalFontName = fonts[i];
            fontnameItem.addActionListener(e -> {
                currentSubTabContainerHandler.setFontName(finalFontName);
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
                currentSubTabContainerHandler.setFontSize(finalFontSize);
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
            });
            fontSizeMenu.add(sizeItem);
        }
        customStyleMenu.add(fontSizeMenu);

        JCheckBoxMenuItem boldMenu = new JCheckBoxMenuItem("Bold");
        boldMenu.setSelected(currentSubTabContainerHandler.isBold());
        boldMenu.addActionListener(e -> {
            currentSubTabContainerHandler.toggleBold();
            sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
        });
        customStyleMenu.add(boldMenu);

        JCheckBoxMenuItem italicMenu = new JCheckBoxMenuItem("Italic");
        italicMenu.setSelected(currentSubTabContainerHandler.isItalic());
        italicMenu.addActionListener(e -> {
            currentSubTabContainerHandler.toggleItalic();
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
                    case "HSL":
                    case "HSV":
                    case "CMYK":
                        colorChooser.removeChooserPanel(p);
                        break;
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
                currentSubTabContainerHandler.setColor(colorChooser.getColor());
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
            }
        });
        customStyleMenu.add(colorMenu);
        popupMenu.add(customStyleMenu);

        JMenuItem pasteStyleSearchTitleMenu = new JMenuItem("Paste Style by Title RegEx Search");
        if (sharedParameters.copiedTabFeaturesObjectStyle == null) {
            pasteStyleSearchTitleMenu.setEnabled(false);
        }
        pasteStyleSearchTitleMenu.addActionListener(e -> {
            if (sharedParameters.copiedTabFeaturesObjectStyle != null) {
                //currentSubTabContainerHandler.updateByTabFeaturesObjectStyle(sharedParameters.copiedTabFeaturesObjectStyle);
                String titleKeyword = UIHelper.showPlainInputMessage("Enter a Regular Expression:", "Search in titles and replace their style", sharedParameters.searchedTabTitleForPasteStyle, sharedParameters.get_mainFrame());
                if (!titleKeyword.isEmpty()) {
                    if (Utilities.isValidRegExPattern(titleKeyword)) {
                        sharedParameters.searchedTabTitleForPasteStyle = titleKeyword;
                        ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentSubTabContainerHandler.currentToolTab);
                        for (SubTabContainerHandler subTabContainerHandlerItem : subTabContainerHandlers) {
                            String subTabTitle = subTabContainerHandlerItem.getTabTitle();
                            if (Pattern.compile(titleKeyword).matcher(subTabTitle).find()) {
                                subTabContainerHandlerItem.updateByTabFeaturesObjectStyle(sharedParameters.copiedTabFeaturesObjectStyle);
                            }
                        }
                        sharedParameters.allSettings.subTabSettings.saveSettings(currentSubTabContainerHandler.currentToolTab);
                        sharedParameters.printDebugMessages("Style pasted in titles which matched: " + titleKeyword);
                    } else {
                        UIHelper.showWarningMessage("Regular expression was invalid.", sharedParameters.get_mainFrame());
                        sharedParameters.printlnError("invalid regex: " + titleKeyword);
                    }
                }

            }
        });
        popupMenu.add(pasteStyleSearchTitleMenu);

        popupMenu.addSeparator();

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

            tabTitle = tabTitle.replaceAll("(?<=[^\\s])\\s+#\\d+\\s*$", "");
            sharedParameters.copiedTabTitle = tabTitle;
            sharedParameters.printDebugMessages("Title copied...");
        });
        popupMenu.add(copyTitleMenu);

        JMenuItem pasteTitleMenu = new JMenuItem("Paste Title");
        if (sharedParameters.copiedTabTitle.isEmpty()) {
            pasteTitleMenu.setEnabled(false);
        } else {
            pasteTitleMenu.setText("Paste Title (" + sharedParameters.copiedTabTitle + ")");
        }

        pasteTitleMenu.addActionListener(e -> {
            if (!sharedParameters.copiedTabTitle.isEmpty()) {
                currentSubTabContainerHandler.setTabTitle(sharedParameters.copiedTabTitle);
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(currentSubTabContainerHandler);
                sharedParameters.printDebugMessages("Title pasted...");
            }
        });
        popupMenu.add(pasteTitleMenu);

        JMenu tabScreenshotMenu = new JMenu("Save Tab Screenshot");
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
                String imageFileLocation = saveLocation + "/" + currentSubTabContainerHandler.getTabTitle().replaceAll("[^a-zA-Z0-9-_\\.]", "_") + "_" + strDate + ".png";

                try{
                    ByteArrayOutputStream os = new ByteArrayOutputStream();
                    ImageIO.write(bufferedImage, "png", os);
                    try(OutputStream outputStream = new FileOutputStream(imageFileLocation)) {
                        os.writeTo(outputStream);
                    }
                }catch(Exception err){
                    sharedParameters.printlnError("Image file could not be saved: " + imageFileLocation);
                    sharedParameters.printDebugMessages(err.getMessage());
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

        popupMenu.addSeparator();

        JMenu jumpMenu = new JMenu("Jump to");
        JMenuItem jumpToFirstTabMenu = new JMenuItem("First Tab");
        if (currentSubTabContainerHandler.getTabIndex() == 0) {
            jumpToFirstTabMenu.setEnabled(false);
        }

        jumpToFirstTabMenu.addActionListener(e -> {
            currentSubTabContainerHandler.parentTabbedPane.setSelectedIndex(0);
        });
        jumpMenu.add(jumpToFirstTabMenu);

        JMenuItem jumpToLastTabMenu = new JMenuItem("Last Tab");
        if (currentSubTabContainerHandler.getTabIndex() == currentSubTabContainerHandler.parentTabbedPane.getTabCount() - 2) {
            jumpToLastTabMenu.setEnabled(false);
        }

        jumpToLastTabMenu.addActionListener(e -> {
            currentSubTabContainerHandler.parentTabbedPane.setSelectedIndex(currentSubTabContainerHandler.parentTabbedPane.getTabCount() - 2);
        });
        jumpMenu.add(jumpToLastTabMenu);

        JMenuItem jumpToNextTabMenu = new JMenuItem("Next Tab");
        if (currentSubTabContainerHandler.getTabIndex() == currentSubTabContainerHandler.parentTabbedPane.getTabCount() - 2) {
            jumpToNextTabMenu.setEnabled(false);
        }

        jumpToNextTabMenu.addActionListener(e -> {
            currentSubTabContainerHandler.parentTabbedPane.setSelectedIndex(currentSubTabContainerHandler.getTabIndex() + 1);
        });
        jumpMenu.add(jumpToNextTabMenu);

        JMenuItem jumpToPreviousTabMenu = new JMenuItem("Previous Tab");
        if (currentSubTabContainerHandler.getTabIndex() == 0) {
            jumpToPreviousTabMenu.setEnabled(false);
        }

        jumpToPreviousTabMenu.addActionListener(e -> {
            currentSubTabContainerHandler.parentTabbedPane.setSelectedIndex(currentSubTabContainerHandler.getTabIndex() - 1);
        });
        jumpMenu.add(jumpToPreviousTabMenu);


        JMenu searchAndJumpMenu = new JMenu("Title RegEx Search");
        JMenuItem jumpToFirstTabByTitleMenu = new JMenuItem("Find (case-sensitive)");

        jumpToFirstTabByTitleMenu.addActionListener(e -> {
            String titleKeyword = UIHelper.showPlainInputMessage("Enter a Regular Expression (case-sensitive):", "Search in titles and jump to tab", sharedParameters.searchedTabTitleForJumpToTab, sharedParameters.get_mainFrame());
            if (!titleKeyword.isEmpty()) {
                boolean result = false;
                if (Utilities.isValidRegExPattern(titleKeyword)) {
                    sharedParameters.searchedTabTitleForJumpToTab = titleKeyword;
                    ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentSubTabContainerHandler.currentToolTab);
                    for (SubTabContainerHandler subTabContainerHandlerItem : subTabContainerHandlers) {
                        String subTabTitle = subTabContainerHandlerItem.getTabTitle();
                        if (Pattern.compile(titleKeyword).matcher(subTabTitle).find()) {
                            subTabContainerHandlerItem.parentTabbedPane.setSelectedIndex(subTabContainerHandlerItem.getTabIndex());
                            result = true;
                            break;
                        }
                    }
                    if (result) {
                        sharedParameters.printDebugMessages("Jumped to first title which matched: " + titleKeyword);
                    } else {
                        sharedParameters.printDebugMessages("No title matched: " + titleKeyword);
                    }

                } else {
                    UIHelper.showWarningMessage("Regular expression was invalid.", sharedParameters.get_mainFrame());
                    sharedParameters.printlnError("invalid regex: " + titleKeyword);
                }
            }
        });
        searchAndJumpMenu.add(jumpToFirstTabByTitleMenu);

        JMenuItem jumpToNextTabByTitleMenu = new JMenuItem("Next");
        if (sharedParameters.searchedTabTitleForJumpToTab.isEmpty() || (currentSubTabContainerHandler.getTabIndex() == currentSubTabContainerHandler.parentTabbedPane.getTabCount() - 2)) {
            jumpToNextTabByTitleMenu.setEnabled(false);
        } else {
            jumpToNextTabByTitleMenu.setText("Next - Search for: " + sharedParameters.searchedTabTitleForJumpToTab);
        }

        jumpToNextTabByTitleMenu.addActionListener(e -> {
            if (!sharedParameters.searchedTabTitleForJumpToTab.isEmpty()) {
                boolean result = false;
                ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentSubTabContainerHandler.currentToolTab);
                for (SubTabContainerHandler subTabContainerHandlerItem : subTabContainerHandlers) {
                    if (subTabContainerHandlerItem.getTabIndex() > currentSubTabContainerHandler.getTabIndex()) {
                        String subTabTitle = subTabContainerHandlerItem.getTabTitle();
                        if (Pattern.compile(sharedParameters.searchedTabTitleForJumpToTab).matcher(subTabTitle).find()) {
                            subTabContainerHandlerItem.parentTabbedPane.setSelectedIndex(subTabContainerHandlerItem.getTabIndex());
                            result = true;
                            break;
                        }
                    }
                }

                if (result) {
                    sharedParameters.printDebugMessages("Next matched title was found");
                } else {
                    sharedParameters.printDebugMessages("No new next match was found");
                }
                sharedParameters.printDebugMessages("Jumped to a next title which matched: " + sharedParameters.searchedTabTitleForJumpToTab);
            }
        });
        searchAndJumpMenu.add(jumpToNextTabByTitleMenu);

        JMenuItem jumpToPreviousTabByTitleMenu = new JMenuItem("Previous");
        if (sharedParameters.searchedTabTitleForJumpToTab.isEmpty() || (currentSubTabContainerHandler.getTabIndex() == 0)) {
            jumpToPreviousTabByTitleMenu.setEnabled(false);
        } else {
            jumpToPreviousTabByTitleMenu.setText("Previous - Search for: " + sharedParameters.searchedTabTitleForJumpToTab);
        }

        jumpToPreviousTabByTitleMenu.addActionListener(e -> {
            if (!sharedParameters.searchedTabTitleForJumpToTab.isEmpty()) {
                boolean result = false;
                ArrayList<SubTabContainerHandler> subTabContainerHandlers = sharedParameters.allSubTabContainerHandlers.get(currentSubTabContainerHandler.currentToolTab);
                for (SubTabContainerHandler subTabContainerHandlerItem : subTabContainerHandlers) {
                    if (subTabContainerHandlerItem.getTabIndex() < currentSubTabContainerHandler.getTabIndex()) {
                        String subTabTitle = subTabContainerHandlerItem.getTabTitle();
                        if (Pattern.compile(sharedParameters.searchedTabTitleForJumpToTab).matcher(subTabTitle).find()) {
                            subTabContainerHandlerItem.parentTabbedPane.setSelectedIndex(subTabContainerHandlerItem.getTabIndex());
                            result = true;
                            break;
                        }
                    }
                }
                if (result) {
                    sharedParameters.printDebugMessages("Previous matched title was found");
                } else {
                    sharedParameters.printDebugMessages("No new previous match was found");
                }

                sharedParameters.printDebugMessages("Jumped to a previous title which matched: " + sharedParameters.searchedTabTitleForJumpToTab);
            }
        });
        searchAndJumpMenu.add(jumpToPreviousTabByTitleMenu);
        jumpMenu.add(searchAndJumpMenu);
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

        JMenuItem jumpToAddTabMenu = new JMenuItem("Add an Empty New Tab");
        jumpToAddTabMenu.addActionListener(e -> {
            Container dotdotdotTabContainer = (Container) currentSubTabContainerHandler.parentTabbedPane.getTabComponentAt(currentSubTabContainerHandler.parentTabbedPane.getTabCount() - 1);
            Component dotdotdotTab = dotdotdotTabContainer.getComponents()[0];
            currentSubTabContainerHandler.parentTabbedPane.setSelectedIndex(currentSubTabContainerHandler.parentTabbedPane.getTabCount() - 1);
            MouseEvent me = new MouseEvent(dotdotdotTab, 0, 0, 0, dotdotdotTab.getLocationOnScreen().x, dotdotdotTab.getLocationOnScreen().y, 1, true);
            for (MouseListener ml : dotdotdotTab.getMouseListeners()) {
                ml.mouseClicked(me);
            }
        });
        popupMenu.add(jumpToAddTabMenu);

        popupMenu.addSeparator();

        BurpUITools.MainTabs tool = currentSubTabContainerHandler.currentToolTab;

        JCheckBoxMenuItem toolSubTabPaneScrollableLayout = new JCheckBoxMenuItem("Scrollable " + tool.toString() + " Tabs");
        if ((boolean) sharedParameters.preferences.getSetting("isScrollable_" + tool.toString())) {
            toolSubTabPaneScrollableLayout.setSelected(true);
        }

        toolSubTabPaneScrollableLayout.addActionListener((e) -> {
            if ((boolean) sharedParameters.preferences.getSetting("isScrollable_" + tool.toString())) {
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        new Thread(() -> {
                            sharedParameters.get_toolTabbedPane(tool).setTabLayoutPolicy(JTabbedPane.WRAP_TAB_LAYOUT);
                        }).start();
                    }
                });
                sharedParameters.allSettings.saveSettings("isScrollable_" + tool.toString(), false);
            } else {
                SwingUtilities.invokeLater(new Runnable() {
                    @Override
                    public void run() {
                        new Thread(() -> {
                            sharedParameters.get_toolTabbedPane(tool).setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);
                            new java.util.Timer().schedule(
                                    new java.util.TimerTask() {
                                        @Override
                                        public void run() {
                                            currentSubTabContainerHandler.parentTabbedPane.setSelectedIndex(0);
                                            currentSubTabContainerHandler.parentTabbedPane.setSelectedIndex(currentSubTabContainerHandler.getTabIndex());
                                        }
                                    },
                                    1000
                            );
                        }).start();
                    }
                });
                sharedParameters.allSettings.saveSettings("isScrollable_" + tool.toString(), true);
            }
        });

        popupMenu.add(toolSubTabPaneScrollableLayout);

        JCheckBoxMenuItem toolSubTabPaneMouseWheelScroll = new JCheckBoxMenuItem(tool.toString() + " Tab Scroll by Mouse Wheel");
        if ((boolean) sharedParameters.preferences.getSetting("mouseWheelToScroll_" + tool.toString())) {
            toolSubTabPaneMouseWheelScroll.setSelected(true);
        }

        toolSubTabPaneMouseWheelScroll.addActionListener((e) -> {
            if ((boolean) sharedParameters.preferences.getSetting("mouseWheelToScroll_" + tool.toString())) {
                BurpUITools.removeMouseWheelFromJTabbedPane(currentSubTabContainerHandler.parentTabbedPane, true);
                sharedParameters.allSettings.saveSettings("mouseWheelToScroll_" + tool.toString(), false);
            } else {
                BurpUITools.addMouseWheelToJTabbedPane(currentSubTabContainerHandler.parentTabbedPane, false);
                sharedParameters.allSettings.saveSettings("mouseWheelToScroll_" + tool.toString(), true);
            }
        });

        popupMenu.add(toolSubTabPaneMouseWheelScroll);

        return popupMenu;
    }
}
