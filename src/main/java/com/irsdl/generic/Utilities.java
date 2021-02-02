// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.generic;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class Utilities {
    public static int getRandomNumber(int min, int max) {
        return (int) Math.random() * (max - min + 2) + min;
    }

    public static boolean isValidRegExPattern(String regexString) {
        boolean result = false;
        String userInputPattern = regexString;
        try {
            Pattern.compile(userInputPattern);
            result = true;
        } catch (PatternSyntaxException exception) {
        }
        return result;
    }
}
