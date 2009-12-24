############
# CURSES
#############

class Gui

  def initialize
    begin 
      # initialize ncurses
      Ncurses.initscr
      Ncurses.cbreak           # provide unbuffered input
      Ncurses.echo           # turn off input echoing
      Ncurses.nl             # turn off newline translation
      Ncurses.stdscr.intrflush(false) # turn off flush-on-interrupt
      Ncurses.stdscr.keypad(true)     # turn on keypad mode
      Ncurses.stdscr.nodelay(false)
      Ncurses.refresh

      # Make our three windows
      @listWindow = Ncurses::WINDOW.new(Ncurses.LINES() - 5, Ncurses.COLS() - 40, 0, 0)
      @detailWindow = Ncurses::WINDOW.new(Ncurses.LINES() - 10, 40, 5, Ncurses.COLS() - 40)
      @termWindow = Ncurses::WINDOW.new(5, Ncurses.COLS(), Ncurses.LINES() - 5, 0)
      @infoWindow = Ncurses::WINDOW.new(5, 40, 0, Ncurses.COLS() - 40)

      # Borders
      @listWindow.border(*([0]*8))
      @detailWindow.border(*([0]*8))
      @termWindow.border(*([0]*8))
      @infoWindow.border(*([0]*8))

      @listWindow.move(1,0)
      @termWindow.move(1,0)
      @detailWindow.move(1,0)
      @infoWindow.move(1,0)

      # Update virtual screen
      @listWindow.noutrefresh() # copy window to virtual screen, don't update real screen
      @detailWindow.noutrefresh()
      @termWindow.noutrefresh()
      @infoWindow.noutrefresh()

      @termWindow.keypad(true)
      @termWindow.nodelay(false)
      
      
      @list = []
      @listStart = 0
      # Refresh screen
      Ncurses.doupdate() # update read screen

    ensure
      Ncurses.echo
      Ncurses.cbreak
      Ncurses.nl
      Ncurses.endwin
    end
  end

  def query(str)
    @termWindow.addstr(" ")
    @termWindow.addstr(str)
    @termWindow.border(*([0]*8))
    @termWindow.noutrefresh()
    Ncurses.doupdate()

    result = ''

    while 1
      input = @termWindow.getch

      # Handle scrolling
      if(input == 338 or input == 258)
        downScroll
        return ''
      elsif(input == 339 or input == 259)
        upScroll
        return ''

      # Backspace just clears line for simplicity
      elsif(input == 8)
        return ''

      # Newline returns result
      elsif(input == 10)
        break

      elsif(input >= 48 and input <=122)
        result += input.chr
        next 

      # Don't know what this would be...return '' to be safe
      else
        return ''
      end
    end

    return result
  end

  def termOut(str)
    @termWindow.addstr(" ")
    @termWindow.addstr(str)
    @termWindow.border(*([0]*8))
    @termWindow.noutrefresh()
    Ncurses.doupdate()
  end

  def termClear
    @termWindow.clear
    @termWindow.border(*([0]*8))
    @termWindow.move(2, 1)
    @termWindow.noutrefresh()
    Ncurses.doupdate()
  end

  def listAdd(str)
    @list.push(str)
  end

  def listPrint
    @listWindow.clear
    @listWindow.move(1,0)
    for i in (@listStart..[Ncurses.LINES() - 5 + @listStart, @list.size-1].min)
      @listWindow.addstr("   ")
      @listWindow.addstr(@list[i])
    end
    @listWindow.border(*([0]*8))
    @listWindow.noutrefresh()
    Ncurses.doupdate()
  end

  def upScroll
    if @listStart > 0
      @listStart -= 1
    end
    listPrint
  end

  def downScroll
    if @listStart < @list.size - Ncurses.LINES() + 8
      @listStart += 1
    end
    listPrint
  end

  def detailPrint(str)
    @detailWindow.addstr("  ")
    @detailWindow.addstr(str)
    @detailWindow.border(*([0]*8))
    @detailWindow.noutrefresh()
    Ncurses.doupdate()
  end

  def detailClear
    @detailWindow.clear
    @detailWindow.border(*([0]*8))
    @detailWindow.move(6, 0)
    @detailWindow.noutrefresh()
    Ncurses.doupdate()
  end

  def infoPrint(str)
    @infoWindow.addstr("  ")
    @infoWindow.addstr(str)
    @infoWindow.border(*([0]*8))
    @infoWindow.noutrefresh()
    Ncurses.doupdate()
  end

  def scrollDown
    @listWindow.scrl 1
    @listWindow.border(*([0]*8))
    @listWindow.noutrefresh()
    Ncurses.doupdate()
  end

  def scrollUp
    @listWindow.scrl -1
    @listWindow.border(*([0]*8))
    @listWindow.noutrefresh()
    Ncurses.doupdate()
  end
end
