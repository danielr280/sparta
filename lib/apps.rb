##########################################
# Apps represent potential attack vectors
##########################################
class App

  # Initialize instance variables
  def initialize(id, path, network, pid, user, ip, transport, remote, port)
    @id = id
    @path = path

    if network
      @pid = pid
      @user =  user
      @ip = ip
      @transport = transport
      @remote = remote
      @port = port
      @network = true
    else @network = false
    end
  end

  # Gather information on the binary
  def resolve

    @perms = Constants::NOTFOUND
    @package = Constants::NOTFOUND
    @version = Constants::NOTFOUND
    @pie = Constants::NOTFOUND
    @stack = Constants::NOTFOUND

    # Get the file permissions
    permline = `#{Constants::LSPATH} -l #@path 2>/dev/null`
    if permline != ''
      @perms = permline[0,10]
    end

    # dpk and apt
    if Constants::PACKAGE == "apt"
      # Default: not found
      @package = Constants::NOTFOUND
      @version = Constants::NOTFOUND

      packageline = `#{Constants::DPKGPATH} --search #@path 2>/dev/null`
      if packageline =~ /([a-zA-Z0-9\-\.]*):.*/
        @package = $1
        versionline = `#{Constants::DPKGPATH} -p #@package 2>/dev/null`
        versionline.each_line do |line|
          if line =~ /Version:\ *([a-zA-Z0-9\-\.:]*)/
            @version = $1
          end
        end
      end

    # rpm
    elsif Constants::PACKAGE == "rpm"
      packageline = `#{Constants::RPM} -qf #@path 2>/dev/null`
      if packageline.size < 1
        @package = Constants::NOTFOUND
        @version = Constants::NOTFOUND
      else
        @package = packageline.chomp
        versionline = `#{Constants::RPM} -qi #@package 2>/dev/null`
        @version = Constants::NOTFOUND
      end
    end

    # Get PIE and stack info
    elfLine = `#{Constants::READELFPATH} -hl #@path 2>/dev/null`
    @pie = Constants::NOTFOUND
    @stack = Constants::NOTFOUND
    elfLine.each_line do |line|
      if line =~ /Type:\ *EXEC.*/
        @pie = "FALSE"
      elsif line =~ /Type:.*/
        @pie = "TRUE"
      elsif line =~ /GNU_STACK\ *0x[0-9a-f]*\ *0x[0-9a-f]*\ *0x[0-9a-f]*\ *0x[0-9a-f]*\ *0x[0-9a-f]*\ *([A-Z]*).*/
        @stack = $1
      end
    end
  end

  def getId
    @id
  end

  def getPackage
    @package
  end

  def getPath
    @path
  end

  # Print menu information
  def print(gui)
    if @network
      gui.listAdd(sprintf("%-5s %-30s %-10s %-10s\n", @id, @path, @port, @remote))
    else
      gui.listAdd(sprintf("%-5s %-30s\n", @id, @path))
    end
  end

  # Print detailed information
  def printDetails(gui)
    gui.detailPrint("Detailed information\n")
    gui.detailPrint("----------------------------------\n\n")
    gui.detailPrint(sprintf("%-10s %-50s\n", "Path", @path))
    gui.detailPrint(sprintf("%-10s %-50s\n", "Perms", @perms))
    gui.detailPrint(sprintf("%-10s %-50s\n", "Package", @package))
    gui.detailPrint(sprintf("%-10s %-50s\n", "Version", @version))
    gui.detailPrint(sprintf("%-10s %-50s\n", "PIE", @pie))
    gui.detailPrint(sprintf("%-10s %-50s\n", "Stack", @stack))

    if @network
      gui.detailPrint(sprintf("%-10s %-50s\n", "PID", @pid))
      gui.detailPrint(sprintf("%-10s %-50s\n", "User", @user))
      gui.detailPrint(sprintf("%-10s %-50s\n", "IP", @ip))
      gui.detailPrint(sprintf("%-10s %-50s\n", "Transport", @transport))
      gui.detailPrint(sprintf("%-10s %-50s\n", "Remote", @remote))
      gui.detailPrint(sprintf("%-10s %-50s\n", "Port", @port))
    end
  end
end

class VulnList

  def initialize(gui)
    @allList = []
    @setuidList = []
    @tcpList = []
    @udpList = []
    @gui = gui
  end

  def setuidAdd(app)
    @setuidList.push(app)
    @allList.push(app)
  end

  def tcpAdd(app)
    @tcpList.push(app)
    @allList.push(app)
  end

  def udpAdd(app)
    @udpList.push(app)
    @allList.push(app)
  end

  def printSetuidList
    @gui.listAdd("Setuid apps:\n")
    @gui.listAdd("\n")
    @gui.listAdd(sprintf("%-5s %-30s\n", "ID", "Path"))
    @gui.listAdd("---------------------\n")
    @setuidList.length.times do |i|
      @setuidList[i].print(@gui)
    end
  end

  def printTcpList
    @gui.listAdd("\n")
    @gui.listAdd("TCP daemons:\n")
    @gui.listAdd("\n")
    @gui.listAdd(sprintf("%-5s %-30s %-10s %-10s\n", "ID", "Path", "Port", "Remote"))
    @gui.listAdd("-------------------------------------------------------------\n")
    @tcpList.length.times do |i|
      @tcpList[i].print(@gui)
    end
  end

  def printUdpList
    @gui.listAdd("\n")
    @gui.listAdd("\n")
    @gui.listAdd("UDP daemons:\n")
    @gui.listAdd("\n")
    @gui.listAdd(sprintf("%-5s %-30s %-10s %-10s\n", "ID", "Path", "Port", "Remote"))
    @gui.listAdd("-------------------------------------------------------------\n")
    @udpList.length.times do |i|
      @udpList[i].print(@gui)
    end
  end

  def getApp(num)
    @allList[num-1]
  end
end

