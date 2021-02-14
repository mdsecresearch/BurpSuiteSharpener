// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.objects;

import java.awt.*;

public class TabFeaturesObject extends TabFeaturesObjectStyle {
    public int index;
    public String title;

    public TabFeaturesObject(int index, String title, String fontName, float fontSize, boolean isBold, boolean isItalic, boolean isCloseButtonVisible, Color colorCode) {
        super("", fontName, fontSize, isBold, isItalic, isCloseButtonVisible, colorCode);
        this.index = index;
        this.title = title;
    }

    @Override
    public boolean equals(Object o) {
        boolean result = false;
        if (o instanceof TabFeaturesObject) {
            TabFeaturesObject temp = (TabFeaturesObject) o;
            if (temp.title.equals(title) && temp.getStyle().equals(getStyle())) {
                result = true;
            }
        }
        return result;
    }

    public TabFeaturesObjectStyle getStyle() {
        return new TabFeaturesObjectStyle("", fontName, fontSize, isBold, isItalic, isCloseButtonVisible, getColorCode());
    }
}
