###########################
# Scanner searches for
# attack vectors and adds
# them to the list
###########################

class Scanner

  # Scanner keeps track of its vulnlist
  def initialize(vulnlist, gui)
    @vulnlist = vulnlist
    @gui = gui
    @@numApps = 0

    if Process.uid != 0

      # Make a dictionary of port-service mappings from the ports.conf file
      @tcpPorts = {}
      portsFile = File.new("conf/tcp.conf", "r")

      while (line = portsFile.gets)
        if line =~ /([0-9]*):([a-zA-Z\-]*)/
          @tcpPorts[$1] = $2
        end
      end
      
      @udpPorts = {}
      portsFile = File.new("conf/udp.conf", "r")

      while (line = portsFile.gets)
        if line =~ /([0-9]*):([a-zA-Z\-]*)/
          @udpPorts[$1] = $2
        end
      end
    end
  end

  # Find all setuid apps in the defined searchpath and add them to the list
  def scanSetuid
    list = `#{Constants::FINDPATH} #{Constants::SEARCHPATH} -perm -4000 2>/dev/null`
    list.each_line do |line|
      @@numApps += 1
      @vulnlist.setuidAdd(App.new(@@numApps, line.chomp, false, nil, nil, nil, nil, nil, nil))
    end
  end

  # Helper function to use ps to resolve binary and user information, given a process name
  def resolvePath(name)
    resolve = `#{Constants::PSPATH} -F -C #{name}`
    
    # Defaults
    user = Constants::NOTFOUND
    path = Constants::NOTFOUND
    pid = Constants::NOTFOUND

    lineNo = 0
    resolve.each_line do |resolveLine|
      if lineNo == 0
        lineNo += 1
        next
      end

      if resolveLine =~ /([0-9a-zA-Z]*)\ *([0-9]*)\ *[0-9]*\ *[0-9]*\ *[0-9]*\ *[0-9]*\ *[0-9]*\ [A-Za-z0-9:]*\ *[A-Za-z0-9\/\?]*\ *[0-9:]*\ *([A-Za-z0-9\/\-]*)/
        user = $1
        pid = $2
        path = $3
        which = `#{Constants::WHICHPATH} #{name}`.chomp
        
        # If it's not an absolute path, or if it's an interpreter (path does not contain name), use "which"
        if (path[0] != 47 and which != '') or (which != '' and which != path and path.index(name) == nil)
          path = which.chomp
        end
        return user, path, pid
      end
    end

    return user, path, pid 
  end

  # Scan for listening TCP daemons
  def scanTcp
    # If we're not root, we'll need to guess
    if Process.uid != 0
      @gui.termOut("Warning: must be root to resolve network services.  Resolution will be attempted using best guesses.\n")

      # Don't add the same service-port pair twice
      check = []

      # Use netstat
      list = `#{Constants::NETSTATPATH} -ant`
     
      list.each_line do |line|
        # IPv4
        if line =~ /tcp\ *[0-9]*\ *[0-9]*\ *([0-9\.]*):([0-9]*)\ *[0-9\.]*:\*\ *LISTEN/
          if @tcpPorts[$2] != nil
            if !check.include?([$2, @tcpPorts[$2]])
              check.push([$2, @tcpPorts[$2]])
              @@numApps += 1
              port = $2
              host = $1
              # Try to resolve process and owner with resolvePath
              resolved = resolvePath(@tcpPorts[$2])

              @vulnlist.tcpAdd(App.new(@@numApps, resolved[1], true, resolved[2], resolved[0], "IP", "TCP", host == '0.0.0.0', port))
            end
          else
            if check.assoc($2) == nil
              check.push([$2, Constants::NOTFOUND])
              @@numApps += 1
              @vulnlist.tcpAdd(App.new(@@numApps, Constants::NOTFOUND, true, Constants::NOTFOUND, Constants::NOTFOUND, "IP", "TCP", $1 == '0.0.0.0', $2))
            end
          end

        # IPv6
        elsif line =~ /tcp6\ *[0-9]*\ *[0-9]*\ *[0-9]*:[0-9]*:([0-9]*):([0-9]*)\ *[0-9]*:[0-9]*:[0-9]*:[0-9\*]*\ *LISTEN/
          if @tcpPorts[$2] != nil
            if !check.include?([$2, @tcpPorts[$2]])
              check.push([$2, @tcpPorts[$2]])
              @@numApps += 1
              resolved = resolvePath(@tcpPorts[$2])
              @vulnlist.tcpAdd(App.new(@@numApps, resolved[1], true, resolved[2], resolved[0], "IPv6", "TCP", $1 != '1', $2))
            end
          else
            if check.assoc($2) == nil
              check.push([$2, Constants::NOTFOUND])
              @@numApps += 1
              @vulnlist.tcpAdd(App.new(@@numApps, Constants::NOTFOUND, true, Constants::NOTFOUND, Constants::NOTFOUND, "IPv6", "TCP", host == '0.0.0.0', $2))
            end
          end
        end
      end
      return
    end

    # If we have root, we can use LSOF to do some of the work for us
    list = `#{Constants::LSOFPATH} -P -i +c 0`
    check = []
    list.each_line do |line|
      # Doesn't care about IPv4 vs IPv6
      if line =~ /([a-zA-Z0-9\-]*)\ *([0-9]*)\ *([a-zA-Z0-9\-]*)\ *[0-9a-z]*\ *([A-Za-z0-9]*)\ *[0-9]*\ *[0-9a-z]*\ *([A-Z]*)\ *([0-9a-z\*\-]*):([0-9]*)\ *\(LISTEN\)/
        if !check.include?([$1,$7])
          check.push([$1,$7])
          @@numApps += 1
          resolved = resolvePath($1)
          @vulnlist.tcpAdd(App.new(@@numApps, resolved[1], true, $2, $3, $4, $5, $6 == '*', $7))
        end
      end
    end
  end

  # Scan listening UDP sockets
  def scanUdp
    # If we're not root, we'll have to guess using ports.conf
    if Process.uid != 0
      @gui.termOut("Warning: must be root to resolve network services.  Resolution will be attempted using best guesses.\n")
    
      # Don't add the same service-port pair twice
      check = []

      # Use netstat
      list = `#{Constants::NETSTATPATH} -anu`
      list.each_line do |line|
        # IPv4
        if line =~ /udp\ *[0-9]*\ *[0-9]*\ *([0-9\.]*):([0-9]*)\ *[0-9\.]*:\*\ */
          port = $2
          host = $1
          if @udpPorts[port] != nil
            if !check.include?([port, @udpPorts[port]])
              check.push([port, @udpPorts[port]])
              @@numApps += 1
              # Try to resolve process and owner with resolvePath
              resolved = resolvePath(@udpPorts[port])
              @vulnlist.udpAdd(App.new(@@numApps, resolved[1], true, resolved[2], resolved[0], "IP", "UDP", host == '0.0.0.0', port))
            end
          else
            if check.assoc($2) == nil
              check.push([$2, Constants::NOTFOUND])
              @@numApps += 1
              @vulnlist.udpAdd(App.new(@@numApps, Constants::NOTFOUND, true, Constants::NOTFOUND, Constants::NOTFOUND, "IP", "UDP", host == '0.0.0.0', port))
            end
          end
        end
      end
      return
    end      

    # If we're root, use lsof to do most of the work
    list = `#{Constants::LSOFPATH} -P -i +c 0`
    check = []
    list.each_line do |line|
      if line =~ /([a-zA-Z0-9-]*)\ *([0-9]*)\ *([a-zA-Z0-9-]*)\ *[0-9a-z]*\ *([A-Za-z0-9]*)\ *[0-9]*\ *[0-9a-z]*\ *(UDP)\ *([0-9a-z\*-]*):([0-9]*)\ */
        
        if !check.include?([$1,$7])
          check.push([$1,$7])
          @@numApps += 1
          resolved = resolvePath($1)
          @vulnlist.udpAdd(App.new(@@numApps, resolved[1], true, $2, $3, $4, $5, $6 == '*', $7))
        end
      end
    end
  end
end

