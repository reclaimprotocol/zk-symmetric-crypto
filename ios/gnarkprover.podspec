#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint gnarkprover.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'gnarkprover'
  s.version          = '0.1.0'
  s.summary          = 'Reclaim Protocol\'s library for creating Zero Knowledge Proofs'
  s.description      = <<-DESC
Reclaim Protocol\'s library for creating Zero Knowledge Proofs
                       DESC
  s.homepage         = 'https://reclaimprotocol.org'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'CreatorOS' => 'mushaheed@creatoros.co' }

  # This will ensure the source files in Classes/ are included in the native
  # builds of apps using this FFI plugin. Podspec does not support relative
  # paths, so Classes contains a forwarder C file that relatively imports
  # `../src/*` so that the C sources can be shared among all target platforms.
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.public_header_files = 'Classes/**/*.h'
  s.vendored_frameworks = 'libgnarkprover.xcframework'
  s.platform = :ios, '10.0'

  # Some frameworks do not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'
end
