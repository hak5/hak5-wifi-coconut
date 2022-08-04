#!/bin/zsh

# Ultimately this should be in a cmake target but getting cmake to build an app
# with multiple executable components is proving extremely difficult.


# Step one:  Make the basic app structure
mkdir WiFiCoconut.app
mkdir WiFiCoconut.app/Contents
mkdir WiFiCoconut.app/Contents/MacOS
mkdir WiFiCoconut.app/Contents/Framework
mkdir WiFiCoconut.app/Contents/Resources

# Step two:  Copy the pieces of the app together
cp wifi_coconut WiFiCoconut.app/Contents/MacOS
cp ../macos/WiFiCoconut WiFiCoconut.app/Contents/MacOS
cp /usr/local/lib/libusb-1.0.0.dylib WiFiCoconut.app/Contents/Framework
cp -r ../libwifiuserspace/firmware WiFiCoconut.app/Contents/Resources
cp ../macos/AppIcon.icns WiFiCoconut.app/Contents/Resources/WiFiCoconut.icns
cp ../macos/Info.plist WiFiCoconut.app/Contents/
cp ../LICENSE WiFiCoconut.app/Contents/Resources
cp ../LICENSE.firmware WiFiCoconut.app/Contents/Resources

# Step three:  Rewrite the native code library path
install_name_tool \
    -change /usr/local/opt/libusb/lib/libusb-1.0.0.dylib @executable_path/../Frameworks/libusb-1.0.0.dylib \
    WiFiCoconut.app/Contents/MacOS/wifi_coconut

# At this point, WiFiCoconut.app should be built

