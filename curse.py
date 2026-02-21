import curses
import time

def main(stdscr):
    # Hide cursor
    curses.start_color()
    curses.use_default_colors()

    curses.init_pair(1, curses.COLOR_GREEN, -1)

    curses.curs_set(0)

    while True:
        stdscr.clear()
        stdscr.noutrefresh()

        # 1. Get the new dimensions of the terminal
        height, width = stdscr.getmaxyx()

        # 2. Define window size (e.g., centered with a small margin)
        win_h, win_w = height - 4, width - 4
        start_y, start_x = 2, 2


        # 3. Basic error handling: ensure window isn't smaller than 0
        if win_h > 0 and win_w > 0:
            win = curses.newwin(win_h, win_w, start_y, start_x)
            win.box()
            win.addstr(1, 2, f"Size: {width}x{height}")
            win.addstr(2, 2, "Resize the terminal to see me move!")
            win.addstr(3, 2, "Press 'q' to quit.")
            win.refresh()

        # 4. Wait for input
        key = stdscr.getch()

        # 5. Check if the user pressed 'q' or if the window resized
        if key == ord('q'):
            break
        elif key == curses.KEY_RESIZE:
            # When KEY_RESIZE is detected, the next loop iteration 
            # will fetch the new getmaxyx() values.
            continue

if __name__ == "__main__":
    curses.wrapper(main)
