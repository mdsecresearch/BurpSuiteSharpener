// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.objects;

import java.awt.*;
import java.io.Serializable;

public class TabFeaturesObjectStyle implements Serializable {
    public String name = "";
    public String fontName = "";
    public float fontSize = 0;
    public boolean isBold = false;
    public boolean isItalic = false;
    public boolean isCloseButtonVisible = false;
    private String iconResourceString = "";
    public int iconSize = 0;
    public String colorCode = "";

    public TabFeaturesObjectStyle(String styleName, String fontName, float fontSize, boolean isBold, boolean isItalic, boolean isCloseButtonVisible, Color colorCode, String iconResourceString, int iconSize) {
        this.name = styleName;
        this.fontName = fontName;
        this.fontSize = fontSize;
        this.isBold = isBold;
        this.isItalic = isItalic;
        this.isCloseButtonVisible = isCloseButtonVisible;
        this.iconResourceString = iconResourceString;
        this.iconSize = iconSize;
        setColor(colorCode);
    }

    public String get_IconResourceString() {
        if (iconResourceString == null)
            iconResourceString = "";
        return iconResourceString.replace(":", "").replace("\\", "/").replaceAll("/+", "/").replaceAll("\\.\\s*+/", "./").replaceAll("/\\s*\\.+", "/.");
    }

    public Color getColor() {
        Color color;
        try {
            color = Color.decode(this.colorCode);
        } catch (Exception e1) {
            // old system
            try {
                color = new Color(Integer.parseInt(this.colorCode), true);
            } catch (Exception e2) {
                color = Color.BLACK;
            }
        }
        return color;
    }

    public void setColor(Color _colorObj) {
        this.colorCode = String.format("#%06x", _colorObj.getRGB() & 0xFFFFFF); // new system!
        // this.colorCode = Integer.toString(_colorObj.getRGB()); // old easy approach!
    }

    @Override
    public boolean equals(Object o) {
        boolean result = false;
        if (o instanceof TabFeaturesObjectStyle) {
            TabFeaturesObjectStyle temp = (TabFeaturesObjectStyle) o;
            if (temp.fontName == fontName && temp.fontSize == fontSize && Boolean.compare(temp.isBold, isBold) == 0 &&
                    Boolean.compare(temp.isItalic, isItalic) == 0 && temp.iconResourceString.equals(iconResourceString) && temp.iconSize == iconSize &&
                    Boolean.compare(temp.isCloseButtonVisible, isCloseButtonVisible) == 0 && temp.colorCode.equals(colorCode)) {
                result = true;
            }
        }
        return result;
    }

    public boolean equalsIgnoreColor(Object o) {
        boolean result = false;
        if (o instanceof TabFeaturesObjectStyle) {
            TabFeaturesObjectStyle temp = (TabFeaturesObjectStyle) o;
            if (temp.fontName.equals(fontName) && temp.fontSize == fontSize && Boolean.compare(temp.isBold, isBold) == 0 &&
                    Boolean.compare(temp.isItalic, isItalic) == 0 && temp.iconResourceString.equals(iconResourceString) && temp.iconSize == iconSize &&
                    Boolean.compare(temp.isCloseButtonVisible, isCloseButtonVisible) == 0) {
                result = true;
            }
        }
        return result;
    }
}
