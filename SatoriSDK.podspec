Pod::Spec.new do |s|
s.name         = "SatoriSDK"
s.version      = "1.0.0"
s.summary      = "An iOS framework for Satori platform."
s.description  = <<-DESC
The SatoriSDK framework for iOS enables you to easily integrate your iOS apps with Satori. Using the framework, you can publish and subscribe messages to RTM.
DESC

s.homepage     = "https://github.com/satori-com"
s.license      = { :type => "Satori Platform License", :file => "LICENSE" }
s.author       = "Satori Worldwide, Inc."
s.platform     = :ios, "8.0"

s.source       = { :git => "https://github.com/satori-com/satori-sdk-c.git", :tag => "v#{s.version}" }
s.source_files  = "ios-framework/SatoriSDK/SatoriSDK/**/*.{h,m}", "core/src/*.{h,c}"
s.public_header_files = "ios-framework/SatoriSDK/SatoriSDK/**/*.h", "core/src/rtm.h"
s.exclude_files = "core/src/rtm_gnutls.c", "core/src/rtm_openssl.c", "core/src/rtm_windows.c"
s.pod_target_xcconfig  = { "HEADER_SEARCH_PATHS" => "$(PODS_TARGET_SRCROOT)/vendor/**", "GCC_PREPROCESSOR_DEFINITIONS" => "USE_APPLE_SSL" }
s.preserve_paths = 'vendor/panzi/portable_endian.h'

end
