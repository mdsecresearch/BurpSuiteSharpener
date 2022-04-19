// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.burp.sharpener.objects;

import java.awt.*;
import java.util.Arrays;

public class TabFeaturesObject extends TabFeaturesObjectStyle {
    public int index = -1;
    public String title = "";
    //public LinkedHashSet<String> titleHistory = new LinkedHashSet<>(); // https://github.com/CoreyD97/BurpExtenderUtilities/issues/7 we still can't keep the order using LinkedHashSet
    public String[] titleHistory = new String[]{};

    public TabFeaturesObject(int index, String title, String[] titleHistory, String fontName, float fontSize, boolean isBold, boolean isItalic, boolean isCloseButtonVisible, Color colorCode, String iconString, int iconSize) {
        super("", fontName, fontSize, isBold, isItalic, isCloseButtonVisible, colorCode, iconString, iconSize);
        this.index = index;
        this.title = title;
        //this.titleHistory = Arrays.stream(titleHistory).filter(s -> (s != null && s.length() > 0)).collect(Collectors.toCollection( LinkedHashSet::new ));
        this.titleHistory = Arrays.stream(titleHistory).filter(s -> (s != null && !s.isBlank())).toArray(String[]::new);
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
        return new TabFeaturesObjectStyle("", fontName, fontSize, isBold, isItalic, isCloseButtonVisible, getColor(), get_IconResourceString(), iconSize);
    }
}
