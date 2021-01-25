# BurpSuiteSharpener
This extension should add a number of UI and functional features to Burp Suite to make working with it easier. 

# Current Features
* Making main tools' tabs more distinguishable by choosing a theme
* Ability to control style of sub-tabs in Repeater and Intruder
* Ability to change Burp Suite title and its icon

# Suggesting New Features
The plan is to add simple but missing features to this single extension to make it a must-have companion when using Burp.
Please feel free to submit your new feature requests using `FR: ` in its title in [issues](https://github.com/mdsecresearch/BurpSuiteSharpener/issues).

It would be great to also list any known available extensions which might have implemented suggested features. 
Perhaps the best features can be imported from different open-source extensions so the overhead of adding different extensions can be reduced.

# Installation
* Download the jar file from the [release](https://github.com/mdsecresearch/BurpSuiteSharpener/tree/main/release) directory or in [artifacts](https://github.com/mdsecresearch/BurpSuiteSharpener/actions)
* Add it to Burp Suite using the Extender tab
  
# Usage Tips
* You can use the following key combinations to access the Repeater and Intruder sub-tab menu:

| Combination | Description |	
| --- | --- |	
|Middle Mouse Click|		Show Context Menu|	
|Middle Click + CTRL|	Increase the Font Size + Bold|	
|Middle Click + CTRL + SHIFT|	Decrease the Font Size + Bold|	
|Middle Click + SHIFT|	Big + Red + Bold|

* Sometimes Right Click + Alt can be used instead of Middle Click
* After setting style on a sub-tab, setting the same title on another sub-tab will copy its style
* Use the `Debug` option in `Global Settings` if you are reporting a bug
* It is always recommended checking the [extension's GitHub repository](https://github.com/mdsecresearch/BurpSuiteSharpener) rather than BApp Store for the latest updates
* A sample of icons and the latest releases should also be accessible in the `/release` directory

# Limitation
* It has been tested against v2.0.x but should work fine against v1.7.x (hopefully)

# Thanks To
* Corey Arthur [CoreyD97](https://twitter.com/CoreyD97
* Bruno Demarche

Please feel free to report bugs, suggest features, or send pull requests.
