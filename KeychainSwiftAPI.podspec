
Pod::Spec.new do |s|
  s.name             = "KeychainSwiftAPI"
  s.version          = "0.2.0"
  s.summary          = "Swift wrapper of iOS C Keychain Framework"
  s.description      = <<-DESC
                        This Keychain Swift API library is a wrapper of iOS C Keychain Framework.
                        It allows easily and securely storing sensitive data in secure keychain store
                        in Swift projects. Interfacing with the original C keychain API is combersome from
                        Swift, and is prone to errors which lead to security vulnerabilities. This
                        library is written according to the best security coding practices and guidelines.
                       DESC
  s.homepage         = "https://github.com/deniskr/KeychainSwiftAPI"
  s.license          = 'MIT'
  s.author           = { "Denis Krivitski" => "denis.krivitski@checkmarx.com" }
  s.source           = { :git => "https://github.com/deniskr/KeychainSwiftAPI.git", :tag => s.version.to_s }
  # s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

  s.platform     = :ios, '8.0'
  s.requires_arc = true

  s.source_files = 'Pod/Classes/*.{h,m,swift}'
  s.resource_bundles = {  }

  s.public_header_files = 'Pod/Classes/**/*.h'
  s.frameworks = 'Security'
end
