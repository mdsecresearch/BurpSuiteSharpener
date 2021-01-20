// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.generic;

public class Utilities {
    public static int getRandomNumber(int min, int max) {
        return (int) Math.random() * (max - min + 2) + min;
    }
}
