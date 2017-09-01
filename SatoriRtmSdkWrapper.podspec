Pod::Spec.new do |s|
s.name         = "SatoriRtmSdkWrapper"
s.version      = "2.0.0"
s.summary      = "An iOS wrapper for C SDK for Satori RTM."
s.description  = <<-DESC
The Satori RTM C SDK wrapper for iOS enables you to integrate your iOS apps with Satori. Using the wrapper, you can publish and subscribe messages to RTM.
DESC

s.homepage     = "https://github.com/satori-com/satori-rtm-sdk-c"
s.license      = { :type => "Satori Platform License", :file => "LICENSE" }
s.author       = "Satori Worldwide, Inc."
s.platform     = :ios, "8.0"

s.source       = { :git => "https://github.com/satori-com/satori-rtm-sdk-c.git", :tag => "v#{s.version}" }
s.source_files  = "ios-wrapper/SatoriRtmSdkWrapper/SatoriRtmSdkWrapper/**/*.{h,m}", "core/src/*.{h,c}", "core/src/io/rtm_posix.c", "core/src/ssl/rtm_apple_ssl.c"
s.public_header_files = "ios-wrapper/SatoriRtmSdkWrapper/SatoriRtmSdkWrapper/**/*.h", "core/src/rtm.h"
s.pod_target_xcconfig  = { "HEADER_SEARCH_PATHS" => "$(PODS_TARGET_SRCROOT)/vendor/**", "GCC_PREPROCESSOR_DEFINITIONS" => "USE_APPLE_SSL" }

end
