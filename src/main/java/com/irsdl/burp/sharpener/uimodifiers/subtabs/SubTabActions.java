// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.uimodifiers.subtabs;

import com.irsdl.burp.sharpener.SharpenerSharedParameters;
import com.irsdl.burp.sharpener.objects.TabFeaturesObjectStyle;
import com.irsdl.generic.JScrollMenu;

import javax.swing.*;
import javax.swing.colorchooser.AbstractColorChooserPanel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.MouseEvent;

public class SubTabActions {
    public static void tabClicked(final MouseEvent e, SharpenerSharedParameters sharedParameters) {
        if (SwingUtilities.isMiddleMouseButton(e) || e.isAltDown() || ((e.getModifiers() & ActionEvent.ALT_MASK) == ActionEvent.ALT_MASK)) {
            if (e.getComponent() instanceof JTabbedPane) {
                JTabbedPane tabbedPane = (JTabbedPane) e.getComponent();
                int tabIndex = tabbedPane.getUI().tabForCoordinate(tabbedPane, e.getX(), e.getY());
                if (tabIndex < 0 || tabIndex > tabbedPane.getTabCount() - 1) return;

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
                    popupMenu.show(tabbedPane, e.getX(), e.getY());
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


    private static JPopupMenu createPopupMenu(SharpenerSharedParameters sharedParameters, SubTabContainerHandler subTabContainerHandler) {
        JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem menuItem = new JMenuItem("Tab Title: " + subTabContainerHandler.getTabTitle());
        menuItem.setEnabled(false);
        popupMenu.add(menuItem);
        popupMenu.addSeparator();

        JMenuItem pasteStyleMenu = new JMenuItem("Paste Style");
        if (sharedParameters.copiedTabFeaturesObjectStyle == null) {
            pasteStyleMenu.setEnabled(false);
        }
        pasteStyleMenu.addActionListener(e -> {
            if (sharedParameters.copiedTabFeaturesObjectStyle != null) {
                subTabContainerHandler.updateByTabFeaturesObjectStyle(sharedParameters.copiedTabFeaturesObjectStyle);
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(subTabContainerHandler);
                sharedParameters.printDebugMessages("Style pasted...");
            }
        });
        popupMenu.add(pasteStyleMenu);

        JMenuItem copyStyleMenu = new JMenuItem("Copy Style");
        if (subTabContainerHandler.isDefault())
            copyStyleMenu.setEnabled(false);
        copyStyleMenu.addActionListener(e -> {
            sharedParameters.copiedTabFeaturesObjectStyle = subTabContainerHandler.getTabFeaturesObjectStyle();
            sharedParameters.printDebugMessages("Style copied...");
        });
        popupMenu.add(copyStyleMenu);


        JCheckBoxMenuItem defaultProfile = new JCheckBoxMenuItem("Reset to Default");
        defaultProfile.addActionListener(e -> {
            subTabContainerHandler.setToDefault();
            sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(subTabContainerHandler);
        });
        if (subTabContainerHandler.isDefault())
            defaultProfile.setEnabled(false);
        popupMenu.add(defaultProfile);

        JMenu profileMenu = new JMenu("Predefined Patterns");

        JCheckBoxMenuItem highProfile = new JCheckBoxMenuItem("High: Red, Big, and Bold");
        highProfile.addActionListener(e -> {
            TabFeaturesObjectStyle tabFeaturesObjectStyle = new TabFeaturesObjectStyle("High: Red, Big, and Bold", "Arial", 18, true, false, false, Color.decode("#f71414"));
            subTabContainerHandler.updateByTabFeaturesObjectStyle(tabFeaturesObjectStyle);
            sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(subTabContainerHandler);
        });
        profileMenu.add(highProfile);

        JCheckBoxMenuItem mediumProfile = new JCheckBoxMenuItem("Medium: Orange, Big, and Bold");
        mediumProfile.addActionListener(e -> {
            TabFeaturesObjectStyle tabFeaturesObjectStyle = new TabFeaturesObjectStyle("Medium: Orange, Big, and Bold", "Arial", 18, true, false, false, Color.decode("#ff7e0d"));
            subTabContainerHandler.updateByTabFeaturesObjectStyle(tabFeaturesObjectStyle);
            sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(subTabContainerHandler);
        });
        profileMenu.add(mediumProfile);

        JCheckBoxMenuItem lowProfile = new JCheckBoxMenuItem("Low: Yellow, Bold");
        lowProfile.addActionListener(e -> {
            TabFeaturesObjectStyle tabFeaturesObjectStyle = new TabFeaturesObjectStyle("Low: Yellow, Bold", "Arial", 14, true, false, false, Color.decode("#ffef0d"));
            subTabContainerHandler.updateByTabFeaturesObjectStyle(tabFeaturesObjectStyle);
            sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(subTabContainerHandler);
        });
        profileMenu.add(lowProfile);

        JCheckBoxMenuItem infoProfile = new JCheckBoxMenuItem("Info: Green, Bold, Italic");
        infoProfile.addActionListener(e -> {
            TabFeaturesObjectStyle tabFeaturesObjectStyle = new TabFeaturesObjectStyle("Info: Green, Bold, Italic", "Arial", 14, true, true, false, Color.decode("#0d9e1e"));
            subTabContainerHandler.updateByTabFeaturesObjectStyle(tabFeaturesObjectStyle);
            sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(subTabContainerHandler);
        });
        profileMenu.add(infoProfile);

        popupMenu.add(profileMenu);
        popupMenu.addSeparator();

        JCheckBoxMenuItem closeButtonMenuItem = new JCheckBoxMenuItem("Remove Close Button");
        closeButtonMenuItem.addActionListener(e -> {
            subTabContainerHandler.setVisibleCloseButton(!closeButtonMenuItem.isSelected());
            sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(subTabContainerHandler);
        });
        closeButtonMenuItem.setSelected(!subTabContainerHandler.getVisibleCloseButton());
        popupMenu.add(closeButtonMenuItem);

        JMenu fontNameMenu = new JScrollMenu("Font Name");
        String[] fonts = GraphicsEnvironment.getLocalGraphicsEnvironment().getAvailableFontFamilyNames();

        for (int i = 0; i < fonts.length; i++) {
            JCheckBoxMenuItem fontnameItem = new JCheckBoxMenuItem(fonts[i]);
            fontnameItem.setSelected(fonts[i].equalsIgnoreCase(subTabContainerHandler.getFontName()));
            String finalFontName = fonts[i];
            fontnameItem.addActionListener(e -> {
                subTabContainerHandler.setFontName(finalFontName);
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(subTabContainerHandler);

            });
            fontNameMenu.add(fontnameItem);
        }

        popupMenu.add(fontNameMenu);

        JMenu fontSizeMenu = new JMenu("Font Size");
        float minFontSize = 10, maxFontSize = 40;
        for (float fontSize = minFontSize; fontSize < maxFontSize; fontSize += 2) {
            JCheckBoxMenuItem sizeItem = new JCheckBoxMenuItem(fontSize + "");
            sizeItem.setSelected(subTabContainerHandler.getFontSize() == fontSize);
            float finalFontSize = fontSize;
            sizeItem.addActionListener(e -> {
                subTabContainerHandler.setFontSize(finalFontSize);
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(subTabContainerHandler);
            });
            fontSizeMenu.add(sizeItem);
        }
        popupMenu.add(fontSizeMenu);

        JCheckBoxMenuItem boldMenu = new JCheckBoxMenuItem("Bold");
        boldMenu.setSelected(subTabContainerHandler.isBold());
        boldMenu.addActionListener(e -> {
            subTabContainerHandler.toggleBold();
            sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(subTabContainerHandler);
        });
        popupMenu.add(boldMenu);

        JCheckBoxMenuItem italicMenu = new JCheckBoxMenuItem("Italic");
        italicMenu.setSelected(subTabContainerHandler.isItalic());
        italicMenu.addActionListener(e -> {
            subTabContainerHandler.toggleItalic();
            sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(subTabContainerHandler);
        });
        popupMenu.add(italicMenu);

        JMenuItem colorMenu = new JMenuItem("Set Foreground Color");
        colorMenu.addActionListener(e -> {
            JColorChooser colorChooser = new JColorChooser();
            // we only want to keep the Swatches panel
            AbstractColorChooserPanel[] panels = colorChooser.getChooserPanels();
            for (AbstractColorChooserPanel p : panels) {
                String displayName = p.getDisplayName();
                switch (displayName) {
                    case "RGB":
                    case "HSL":
                    case "HSV":
                    case "CMYK":
                        colorChooser.removeChooserPanel(p);
                        break;
                }
            }
            //Color color = colorChooser.showDialog(colorMenu, "Change Color", subTabContainerHandler.getColor());
            colorChooser.setColor(subTabContainerHandler.getColor());
            JDialog dialog = JColorChooser.createDialog(
                    sharedParameters.get_mainFrame(),
                    "Choose a Color",
                    true,
                    colorChooser,
                    null,
                    null);
            dialog.setVisible(true);
            if (colorChooser.getColor() != null) {
                subTabContainerHandler.setColor(colorChooser.getColor());
                sharedParameters.allSettings.subTabSettings.prepareAndSaveSettings(subTabContainerHandler);
            }
        });
        popupMenu.add(colorMenu);
        return popupMenu;
    }
}
