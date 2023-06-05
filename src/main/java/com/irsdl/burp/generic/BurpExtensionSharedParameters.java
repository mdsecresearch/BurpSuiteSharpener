// Released under AGPL see LICENSE for more information
// Developed by Soroush Dalili (@irsdl)

package com.irsdl.burp.generic;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import com.coreyd97.BurpExtenderUtilities.DefaultGsonProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.irsdl.generic.uiObjFinder.UiSpecObject;
import com.irsdl.generic.uiObjFinder.UIWalker;

import javax.swing.*;
import java.awt.*;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;

public class BurpExtensionSharedParameters {

    public String version = "0.0"; // we need to keep this a double number to make sure check for update can work
    public String extensionName = "MyExtension";
    public String extensionURL = "https://github.com/user/proj";
    public String extensionIssueTracker = "https://github.com/user/proj/issues";
    public String extensionCopyrightMessage = "This has been developed by XXX from YYY";
    public String extensionPropertiesUrl = "https://raw.githubusercontent.com/user/proj/main/src/main/resources/extension.properties"; // can be used in check for update!
    public Integer debugLevel = null;
    public BurpExtension burpExtender;
    public Class extensionClass = null; // this is useful when trying to load a resource such as an image
    public PrintWriter stdout = null;
    public PrintWriter stderr = null;
    public MontoyaApi montoyaApi = null;
    public BurpExtensionFeatures features = new BurpExtensionFeatures();
    public ExtendedPreferences preferences; // to use the ability of this project: https://github.com/CoreyD97/BurpExtenderUtilities
    public boolean unloadWithoutSave = false; // this is useful if we need to exit without save in some situation
    public boolean isBurpPro = false;
    public double burpMajorVersion = 0.0;
    public double burpMinorVersion = 0.0;
    public boolean isCompatibleWithCurrentBurpVersion = true;

    // these are the parameters which are used per extension but needs to be shared - like registers
    public boolean addedIconListener = false;

    public boolean isDarkMode = false; // Sometimes extensions need to see whether Burp uses dark or light mode

    public JComponent extensionSuiteTab = null; // panel that extension adds to burp
    public Registration extensionSuiteTabRegistration = new Registration() {
        @Override
        public boolean isRegistered() {
            return false;
        }

        @Override
        public void deregister() {

        }
    }; // this has been initialised to prevent null exception when it has not been set

    public ContextMenuItemsProvider extensionMainContextMenu = null; // panel that extension adds to burp
    public Registration extensionContextMenuRegistration = new Registration() {
        @Override
        public boolean isRegistered() {
            return false;
        }

        @Override
        public void deregister() {

        }
    }; // this has been initialised to prevent null exception when it has not been set

    // params with custom getter or setter - the `setUIParametersUsingMontoya` or `setUIParametersFromExtensionTabLegacy` method should be used to set them
    // private final JFrame _mainFrameLegacy = null; // This is Burp Suite's main jFrame
    private JMenuBar _mainMenuBar = null; // This is Burp Suite's main menu bar
    private JTabbedPane _rootTabbedPane = null; // this is where Burp Suite main tools' tabs are
    private String _originalBurpTitle = ""; // Burp Suite's original frame title
    private Image _originalBurpIcon = null; // Burp Suite's original frame icon
    private boolean _isUILoaded = false; // Burp Suite's original frame icon

    public enum DebugLevels{
                None("Disabled", 0),
                Verbose("Verbose", 1),
                VerboseAndPrefsRW("Verbose + Show Preferences Read/Write", 2),
                VeryVerbose("Very Verbose", 3),
        ;

        private final String name;
        private final int value;

        DebugLevels(final String name, final int value) {
            this.name = name;
            this.value = value;
        }

        /* (non-Javadoc)
         * @see java.lang.Enum#toString()
         */
        @Override
        public String toString() {
            return name;
        }

        public int getValue() { return value; }

        public String getName() { return name; }

    }

    public BurpExtensionSharedParameters(){

    }

    public BurpExtensionSharedParameters(String version, String extensionName, String extensionURL, String extensionIssueTracker, String extensionCopyrightMessage, String extensionPropertiesUrl, BurpExtension burpExtenderObj, MontoyaApi montoyaApi, BurpExtensionFeatures burpExtensionFeatures) {
        this.version = version;
        this.extensionName = extensionName;
        this.extensionURL = extensionURL;
        this.extensionIssueTracker = extensionIssueTracker;
        this.extensionCopyrightMessage = extensionCopyrightMessage;
        this.extensionPropertiesUrl = extensionPropertiesUrl;
        this.extensionClass = burpExtenderObj.getClass();
        this.burpExtender = burpExtenderObj;
        this.montoyaApi = montoyaApi;
        this.features = burpExtensionFeatures;

        // obtain our output stream
        this.stdout = new PrintWriter(montoyaApi.logging().output(), true);
        this.stderr = new PrintWriter(montoyaApi.logging().error(), true);

        this.printlnOutput(extensionName + " is being loaded...");

        // getting Burp Suite version
        try {
            if (montoyaApi.burpSuite().version().edition().name().toLowerCase().contains("professional"))
                this.isBurpPro = true;

            this.burpMajorVersion = Double.parseDouble(montoyaApi.burpSuite().version().major());
            this.burpMinorVersion = Double.parseDouble(montoyaApi.burpSuite().version().minor());

        } catch (Exception e) {
            printlnError(e.getMessage());
        }

        // initialize custom preferences - see https://github.com/CoreyD97/BurpExtenderUtilities/blob/master/src/test/java/extension/PreferencesTest.java
        this.preferences = new ExtendedPreferences(montoyaApi, new DefaultGsonProvider());
        this.preferences.sharedParameters = this;
        // registering and getting the isDebug setting
        try {
            preferences.registerSetting("debugLevel", Integer.TYPE, 0, Preferences.Visibility.GLOBAL);
        } catch (Exception e) {
            // already registered!
            printlnError(e.getMessage());
        }
        debugLevel = preferences.getSetting("debugLevel");

        // print the copyright message
        this.printlnOutput(extensionCopyrightMessage);

        isCompatibleWithCurrentBurpVersion = isBurpVersionCompatible();
        if(!isCompatibleWithCurrentBurpVersion){
            printlnError("This extension IS NOT COMPATIBLE with the currently used version or edition of Burp Suite.");
            printlnError("Current Burp Suite Version: Major: " + this.burpMajorVersion + " - Minor: " + this.burpMinorVersion);
            printlnError("Current Burp Suite Edition: " + montoyaApi.burpSuite().version().edition().name());
        }else{
            printDebugMessage("This extension is compatible with the currently used version and edition of Burp Suite.");
        }
    }

    private boolean isBurpVersionCompatible(){
        boolean isCompatible = true;
        if (features.maxSupportedMajorVersionInclusive < features.minSupportedMajorVersionInclusive){
            features.maxSupportedMajorVersionInclusive = 0;
        }
        if (features.maxSupportedMajorVersionInclusive <= 0){
            features.maxSupportedMajorVersionInclusive = 0;
            features.maxSupportedMinorVersionInclusive = 0;
        }
        if (features.minSupportedMajorVersionInclusive <= 0){
            features.minSupportedMajorVersionInclusive = 0;
            features.minSupportedMinorVersionInclusive = 0;
        }

        if(features.maxSupportedMajorVersionInclusive > 0){
            if(burpMajorVersion > features.maxSupportedMajorVersionInclusive){
                printlnError("Max Supported Major Version Inclusive: " + features.maxSupportedMajorVersionInclusive);
                printlnError("Max Supported Minor Version Inclusive: " + features.maxSupportedMinorVersionInclusive);
                return false;
            }
            if(burpMajorVersion == features.maxSupportedMajorVersionInclusive && burpMinorVersion > features.maxSupportedMinorVersionInclusive){
                printlnError("Max Supported Major Version Inclusive: " + features.maxSupportedMajorVersionInclusive);
                printlnError("Max Supported Minor Version Inclusive: " + features.maxSupportedMinorVersionInclusive);
                return false;
            }
        }

        if(features.minSupportedMajorVersionInclusive > 0){
            if(burpMajorVersion < features.minSupportedMajorVersionInclusive){
                printlnError("Min Supported Major Version Inclusive: " + features.minSupportedMajorVersionInclusive);
                printlnError("Min Supported Minor Version Inclusive: " + features.minSupportedMinorVersionInclusive);
                return false;
            }
            if(burpMajorVersion == features.minSupportedMajorVersionInclusive && burpMinorVersion < features.minSupportedMinorVersionInclusive){
                printlnError("Min Supported Major Version Inclusive: " + features.minSupportedMajorVersionInclusive);
                printlnError("Min Supported Minor Version Inclusive: " + features.minSupportedMinorVersionInclusive);
                return false;
            }
        }

        if(!features.isCommunityVersionCompatible && !isBurpPro){
            printlnError("This extension is not compatible with the Community edition");
            return false;
        }

        return isCompatible;
    }

    public void setUIParametersUsingMontoya(int maxLoadAttempts) {
        boolean foundUI = false;
        int attemptsRemaining = maxLoadAttempts;

        while (!foundUI && attemptsRemaining > 0) {
            try {

                if (get_rootTabbedPaneUsingMontoya() != null && get_mainFrameUsingMontoya() != null && get_mainFrameUsingMontoya().getRootPane() != null) {
                    isDarkMode = BurpUITools.isDarkMode(get_rootTabbedPaneUsingMontoya());
                    foundUI = true;
                } else
                    throw new Exception("no ui");

                printDebugMessage("UI parameters have been loaded successfully");

            } catch (Exception e) {
                attemptsRemaining--;
                try {
                    Thread.sleep(1000L * (maxLoadAttempts-attemptsRemaining)); // 100 * `waitSeconds` * 10 = `waitSeconds` seconds
                } catch (InterruptedException ignored) {
                }
            }
        }

        if (!foundUI) {
            printlnError(extensionName + " extension UI elements could not be added. Please try again.");
            printDebugMessage("Perhaps unload the extension at this point");
        } else {
            _originalBurpTitle = get_mainFrameUsingMontoya().getTitle();
            _originalBurpIcon = get_mainFrameUsingMontoya().getIconImage();

            printDebugMessage("Original title and icon has been set");
        }
        _isUILoaded = foundUI;
    }

    public void printDebugMessage(String message, String note, boolean alreadyPrinted, int requiredDebugLevel) {
        if (debugLevel != null && debugLevel >= requiredDebugLevel && !message.isEmpty()) {
            printDebugMessage(message, note, alreadyPrinted);
        }
    }

    public void printDebugMessage(String message, String note, boolean alreadyPrinted) {
        if (debugLevel != null && debugLevel > 0 && !message.isEmpty()) {
            String strDate = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
            String fullMessage = "\r\nDEBUG->\r\n\t";
            if (!note.isBlank())
                fullMessage += "Note: " + note + " - Timestamp: " + strDate + "\r\n\tMessage: " + message;
            else
                fullMessage += "Timestamp: " + strDate + "\r\n\tMessage: " + message;
            System.out.println(fullMessage);
            if (!alreadyPrinted) {
                this.stdout.println(fullMessage);
            }
        }
    }

    public void printDebugMessage(String message, int requiredDebugLevel) {
        if (debugLevel != null && debugLevel >= requiredDebugLevel && !message.isEmpty()) {
            printDebugMessage(message);
        }
    }
    public void printDebugMessage(String message) {
        if (debugLevel != null && debugLevel > 0 && !message.isEmpty()) {
            StackTraceElement[] stackTraceElements = Thread.currentThread().getStackTrace();
            StringBuilder methods = new StringBuilder();
            if (debugLevel >= DebugLevels.VeryVerbose.value) {
                methods.append("\t\t");
                // very verbose
                for (int i = 2; i < stackTraceElements.length; i++) {
                    methods.append(stackTraceElements[i]).append(" <- ");
                }
            }

            printDebugMessage(message, methods.toString(), false);
        }
    }

    public void printException(Exception error) {
        if(error != null) {
            this.stderr.println(error.getMessage());

            for (StackTraceElement elem : error.getStackTrace()) {
                this.stderr.println(elem);
            }

            error.printStackTrace();
        }
    }
    public void printlnError(String message) {
        if(!message.isEmpty()){
            this.stderr.println(message);
            printDebugMessage(message, "printlnError", true);
        }
    }

    public void printError(String message) {
        if(!message.isEmpty()){
            this.stderr.print(message);
            printDebugMessage(message, "printError", true);
        }
    }

    public void printlnOutput(String message) {
        if(!message.isEmpty()){
            this.stdout.println(message);
            printDebugMessage(message, "printlnOutput", true);
        }
    }

    public void printOutput(String message) {
        if(!message.isEmpty()){
            this.stdout.print(message);
            printDebugMessage(message, "printOutput", true);
        }
    }

    public void resetAllSettings() {
        // A bug in resetting settings in BurpExtenderUtilities should be fixed, so we will give it another chance instead of using this method
        // preferences.resetAllSettings();

        HashMap<String, Preferences.Visibility> registeredSettings = preferences.getRegisteredSettings();
        for (String item : registeredSettings.keySet()) {
            if (preferences.getSettingType(item) == String.class)
                preferences.setSetting(item, "");
            else
                preferences.setSetting(item, null);
        }

    }

    public JFrame get_mainFrameUsingMontoya() {
        return (JFrame) montoyaApi.userInterface().swingUtils().suiteFrame();
    }

    public JMenuBar get_mainMenuBarUsingMontoya() {
        JMenuBar mainMenuBar = get_mainFrameUsingMontoya().getJMenuBar();
        if (!mainMenuBar.equals(_mainMenuBar)) {
            set_mainMenuBar(mainMenuBar);
        }

        return _mainMenuBar;
    }

    public JTabbedPane get_rootTabbedPaneUsingMontoya() {
        if (this._rootTabbedPane == null) {
            try {
                JRootPane rootPane = ((JFrame) montoyaApi.userInterface().swingUtils().suiteFrame()).getRootPane();
                set_rootTabbedPane((JTabbedPane) rootPane.getContentPane().getComponent(0));
            } catch (Exception e) {
                // This is to find the root of the Burp Suite frame when the above fails
                // We should not really be here
                printlnError("A failure in get_rootTabbedPaneUsingMontoya() has occurred. Hopefully this will be recovered now.");
                // Defining how our Burp Suite frame is
                UiSpecObject uiSpecObject = new UiSpecObject();
                uiSpecObject.set_objectType(JFrame.class);
                uiSpecObject.set_isShowing(true);

                JRootPane rootPane = ((JFrame) UIWalker.FindUIObjectInComponents(JFrame.getWindows(), uiSpecObject)).getRootPane();
                set_rootTabbedPane((JTabbedPane) rootPane.getContentPane().getComponent(0));
            }
        }
        return this._rootTabbedPane;
    }


    private void set_mainMenuBar(JMenuBar mainMenuBar) {
        this._mainMenuBar = mainMenuBar;
    }

    private void set_rootTabbedPane(JTabbedPane rootTabbedPane) {
        this._rootTabbedPane = rootTabbedPane;
    }

    public String get_originalBurpTitle() {
        return _originalBurpTitle;
    }

    public Image get_originalBurpIcon() {
        return _originalBurpIcon;
    }

    public boolean get_isUILoaded() {
        return _isUILoaded;
    }

    // These are the legacy code needed for previous version of Burp Suite - before 2023.1
    // These are kept as a guide for the time being
/*
    public void setUIParametersFromExtensionTabLegacy(JComponent extensionSuiteTab, int maxLoadAttempts) {
        boolean foundUI = false;
        int attemptsRemaining = maxLoadAttempts;

        while (!foundUI && attemptsRemaining > 0) {
            try {
                if (extensionSuiteTab != null) {
                    set_extensionSuiteTabLegacy(extensionSuiteTab);
                }

                if (get_rootTabbedPaneLegacy() != null && get_mainFrameLegacy() != null && get_mainFrameLegacy().getRootPane() != null) {
                    isDarkMode = BurpUITools.isDarkMode(get_rootTabbedPaneLegacy());
                    foundUI = true;
                } else
                    throw new Exception("no ui");

                printDebugMessage("UI parameters have been loaded successfully");

            } catch (Exception e) {
                attemptsRemaining--;
                try {
                    Thread.sleep(1000 * (maxLoadAttempts-attemptsRemaining)); // 100 * `waitSeconds` * 10 = `waitSeconds` seconds
                } catch (InterruptedException ignored) {
                }
            }
        }

        if (!foundUI) {
            printlnError(extensionName + " extension UI elements could not be added. Please try again.");
            printDebugMessage("Perhaps unload the extension at this point");
        } else {
            _originalBurpTitle = get_mainFrameLegacy().getTitle();
            _originalBurpIcon = get_mainFrameLegacy().getIconImage();

            printDebugMessage("Original title and icon has been set");
        }
        _isUILoaded = foundUI;
    }

    private void set_extensionSuiteTabLegacy(JComponent extensionSuiteTab) {
        this.extensionSuiteTab = extensionSuiteTab;
        try{
            JRootPane rootPane = ((JFrame) SwingUtilities.getWindowAncestor(extensionSuiteTab)).getRootPane();
            set_rootTabbedPaneLegacy((JTabbedPane) rootPane.getContentPane().getComponent(0));
        }catch(Exception e){
            // This is to find the root of the Burp Suite frame when our poor JPanel is lost (since Burp v2022.9.5)
            // Defining how our Burp Suite frame is
            UiSpecObject uiSpecObject = new UISpecObject();
            uiSpecObject.set_objectType(JFrame.class);
            uiSpecObject.set_isShowing(true);

            JRootPane rootPane = ((JFrame) UIWalker.FindUIObjectInComponents(JFrame.getWindows(), uiSpecObject)).getRootPane();
            set_rootTabbedPaneLegacy((JTabbedPane) rootPane.getContentPane().getComponent(0));
        }

    }

    public JTabbedPane get_rootTabbedPaneLegacy() {
        return _rootTabbedPane;
    }

    private void set_rootTabbedPaneLegacy(JTabbedPane rootTabbedPane) {
        this._rootTabbedPane = rootTabbedPane;
        JFrame mainFrame = (JFrame) rootTabbedPane.getRootPane().getParent();
        if (!mainFrame.equals(get_mainFrameLegacy())) {
            set_mainFrameLegacy(mainFrame);
        }
    }


    private void set_mainFrameLegacy(JFrame mainFrame) {
        this._mainFrameLegacy = mainFrame;
        JMenuBar mainMenuBar = mainFrame.getJMenuBar();
        if (!mainMenuBar.equals(get_mainMenuBarLegacy())) {
            set_mainMenuBar(mainMenuBar);
        }
    }

    public JMenuBar get_mainMenuBarLegacy() {
        if(_mainMenuBar == null){
            _mainMenuBar = _mainFrameLegacy.getJMenuBar();
        }
        return _mainMenuBar;
    }

    public JFrame get_mainFrameLegacy() {
        return _mainFrameLegacy;
    }
*/

}
