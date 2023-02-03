// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.generic;

import java.util.Random;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class Utilities {
    public static int getInsecureRandomNumber(int min, int max) {
        //return new Random().nextInt(min, max+1);
        Random rand = new Random();
        return rand.nextInt((max - min) + 1) + min;
    }

    public static boolean isValidRegExPattern(String regexString) {
        boolean result = false;
        try {
            Pattern.compile(regexString);
            result = true;
        } catch (PatternSyntaxException exception) {
            //ignore
        }
        return result;
    }
}
