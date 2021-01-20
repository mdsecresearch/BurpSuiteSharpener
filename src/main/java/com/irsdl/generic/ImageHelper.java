// Burp Suite Sharpener
// Released as open source by MDSec - https://www.mdsec.co.uk
// Developed by Soroush Dalili (@irsdl)
// Project link: https://github.com/mdsecresearch/BurpSuiteSharpener
// Released under AGPL see LICENSE for more information

package com.irsdl.generic;

import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;
import java.net.URL;

public class ImageHelper {
    public static Image scaleImageToWidth(BufferedImage image, int width) {
        if (image == null)
            return null;

        int height = (int) (Math.floor((image.getHeight() * width) / (double) image.getWidth()));
        return image.getScaledInstance(width, height, Image.SCALE_SMOOTH);
    }

    public static BufferedImage loadImageResource(String filename) {
        return loadImageResource(filename, UIHelper.class);
    }

    public static BufferedImage loadImageResource(String filename, Class claz) {
        URL imageURLMain = claz.getResource(filename);
        if (imageURLMain != null) {
            Image original = new ImageIcon(imageURLMain).getImage();
            ImageIcon originalIcon = new ImageIcon(original);
            BufferedImage bufferedImage = new BufferedImage(originalIcon.getIconWidth(), originalIcon.getIconHeight(), BufferedImage.TYPE_INT_ARGB);
            Graphics2D g = (Graphics2D) bufferedImage.getGraphics();
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.drawImage(originalIcon.getImage(), null, null);
            return bufferedImage;
        }
        return null;
    }

    public static BufferedImage loadImageFile(String filePath) {
        BufferedImage bufferedImage = null;
        File file = new File(filePath);

        if (file.exists() && file.isFile()) {
            try {
                Image original = new ImageIcon(filePath).getImage();
                ImageIcon originalIcon = new ImageIcon(original);
                bufferedImage = new BufferedImage(originalIcon.getIconWidth(), originalIcon.getIconHeight(), BufferedImage.TYPE_INT_ARGB);
                Graphics2D g = (Graphics2D) bufferedImage.getGraphics();
                g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                g.drawImage(originalIcon.getImage(), null, null);
            } catch (Exception e) {
            }
        }
        return bufferedImage;
    }
}
