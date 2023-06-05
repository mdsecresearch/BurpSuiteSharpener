// Burp Suite Extension Name: Sharpener
// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)
// Released initially as open source by MDSec - https://www.mdsec.co.uk
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener

package com.mdsec.burp.sharpener.objects;

import java.awt.*;
import java.util.Arrays;

public class TabFeaturesObject extends TabFeaturesObjectStyle {
    public int index = -1;
    private String title = ""; // we are trimming the titles since Sharpener 3.2
    private String tfoTitle = ""; // we use this for comparison as it contains trimmed and lowercase values

    //public LinkedHashSet<String> titleHistory = new LinkedHashSet<>(); // https://github.com/CoreyD97/BurpExtenderUtilities/issues/7 we still can't keep the order using LinkedHashSet
    private String[] titleHistory = new String[]{};

    public TabFeaturesObject(){
        super();
    }

    public TabFeaturesObject(int index, String title, String[] titleHistory, String fontName, float fontSize, boolean isBold, boolean isItalic, boolean isCloseButtonVisible, Color colorCode, String iconString, int iconSize) {
        super("", fontName, fontSize, isBold, isItalic, isCloseButtonVisible, colorCode, iconString, iconSize);
        this.index = index;
        this.setTitle(title);
        this.setTitleHistory(titleHistory);
    }

    @Override
    public boolean equals(Object o) {
        boolean result = false;
        if (o instanceof TabFeaturesObject temp) {
            if (temp.getTfoTitle().equals(getTfoTitle()) && temp.getStyle().equals(getStyle())) {
                result = true;
            }
        }
        return result;
    }

    public TabFeaturesObjectStyle getStyle() {
        return new TabFeaturesObjectStyle("", fontName, fontSize, isBold, isItalic, isCloseButtonVisible, getColor(), get_IconResourceString(), iconSize);
    }

    public String getTitle() {
        return title.trim();
    }

    public void setTitle(String title) {
        this.title = title.trim();
        setTfoTitle(title);
    }

    public String[] getTitleHistory() {
        return Arrays.stream(titleHistory).filter(s -> (s != null && !s.isBlank()))
                .map(String::trim)
                .toArray(String[]::new);
    }

    public void setTitleHistory(String[] titleHistory) {
        this.titleHistory = Arrays.stream(titleHistory).filter(s -> (s != null && !s.isBlank()))
                .map(String::trim)
                .toArray(String[]::new);
    }

    public String getTfoTitle() {
        return tfoTitle.toLowerCase().trim();
    }

    private void setTfoTitle(String tfoTitle) {
        this.tfoTitle = tfoTitle.toLowerCase().trim();
    }
}
