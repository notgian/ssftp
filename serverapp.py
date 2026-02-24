import curses
import logging
import ssftp
import ssftp_server as srvr
from threading import Thread
from time import sleep
from collections import deque


class CursesHandler(logging.Handler):
    def __init__(self, display_list):
        super().__init__()
        self.display_list = display_list

    def emit(self, record):
        try:
            msg = self.format(record)
            self.display_list.append(msg)
        except Exception:
            self.handleError(record)

    # Add these two methods to satisfy stream-based expectations
    def write(self, data):
        if data.strip(): # Avoid adding empty newlines
            self.display_list.append(data.strip())

    def flush(self):
        pass


def main(stdscr):
    # Hide cursor
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)
    curses.curs_set(0)

    MAX_LOGS = 5000
    logs = deque(maxlen=MAX_LOGS)
    vertical_scroll = 0
    horizontal_scroll = 0

    logger = logging.getLogger("CursesLog")
    logger.setLevel(logging.DEBUG)
    handler = CursesHandler(logs)

    ssftp_server = srvr.SSFTPServer(handler)
    ssftp_server.new_conn_listen()

    Thread(target=ssftp_server.new_conn_listen, daemon=True).start()

    headerwin = curses.newwin(1, 100, 0, 0)

    logwin = curses.newwin(10, 10, 0, 0)
    logpad = curses.newpad(MAX_LOGS, 500)  # hardcoding the length ig kek

    connwin = curses.newwin(10, 10, 0, 0)

    extrawin = curses.newwin(10, 10, 0, 0)

    footerwin = curses.newwin(1, 10, 0, 0)

    while True:
        stdscr.erase()
        stdscr.noutrefresh()
        stdscr.nodelay(True)

        height, width = stdscr.getmaxyx()
        win_h, win_w = height - 2, width - 2

        if win_h <= 0 or win_w <= 0:
            continue

        # Draw headerwin
        app_title="SSFTP Server"
        title_start = max(0, (win_w // 2) - (len(app_title) // 2))
        try:
            headerwin.erase()
            headerwin.resize(1, win_w)
            headerwin.mvwin(0,0)
            headerwin.addstr(0, title_start, app_title[:win_w-1], curses.A_BOLD)
            headerwin.noutrefresh()
        except curses.error:
            pass

        # Draw the logwin
        logwin_h = 2 * win_h // 3
        logwin_w = win_w
        logwin_x, logwin_y = 1, 1
        try:
            logwin.erase()
            logwin.box()
            logwin.resize(logwin_h, logwin_w)
            logwin.mvwin(logwin_y, logwin_x)
            logwin.addstr(0, logwin_x+1, " LOGS ", curses.A_BOLD)

            bottom_bar_text = "SCROLLING: UP (↑) and DOWN (↓) to scroll vertically. LEFT (←) and RIGHT (→) to scroll horizontally." 
            if len(bottom_bar_text) >= logwin_w:
                bottom_bar_text = "SCROLLING: UP (↑) DOWN (↓) LEFT (←) RIGHT (→)." 
            bottom_bar_text = bottom_bar_text.center(logwin_w-2, " ")
            logwin.addstr(logwin_h-2, 1, bottom_bar_text, curses.A_REVERSE)
        except curses.error:
            pass

        # Draw contents of logpad
        logpad_x, logpad_y = logwin_x + 2, logwin_y + 1
        logpad_h, logpad_w = logwin_h - 2, logwin_w - 2
        for i, line in enumerate(logs):
            try:
                logpad.addstr(i, 0, line[:width-1])
            except curses.error:
                pass

        # Draw connections window (connwin)
        connwin_x, connwin_y = logwin_x, logwin_y + logwin_h
        connwin_h, connwin_w = win_h - logwin_h, 2 * win_w // 3
        try:
            connwin.erase()
            connwin.box()
            connwin.resize(connwin_h, connwin_w)
            connwin.mvwin(connwin_y, connwin_x)
            connwin.addstr(0, 2, " CONNECTIONS ", curses.A_BOLD)

            if len(ssftp_server.connections) == 0:
                inner_text = "No active connections."
                connwin.addstr(connwin_h // 2, (connwin_w - len(inner_text)) // 2,inner_text, curses.A_DIM)
            else:
                i = 0
                for conn_name in list(ssftp_server.connections.keys()):
                    conn = ssftp_server.connections[conn_name]
                    addr = conn_name
                    state = "IDLE" if conn["state"] == 0 else "IN TRANSFER"
                    op = "..."
                    if "op" in conn["options"]:
                        op = "DWN" if conn["options"]["op"] == ssftp.OPCODE.DWN.value.get_int() else "UPL"
                    filename = "..." if "filename" not in conn["options"] else conn["options"]["filename"]
                    block = None if "block" not in conn["options"] else int(conn["options"]["block"])
                    blksize = None if "blksize" not in conn["options"] else int(conn["options"]["blksize"])
                    tsize = "..." if "tsize" not in conn["options"] else int(conn["options"]["tsize"])
                    transferred = "..." if block is None or blksize is None else block * blksize
                    # filename = conn["options"]["filename"]

                    max_len = 25
                    connwin.addstr(2, 2 + i * (2+max_len),f"{addr[0]}:{addr[1]}".center(max_len, " "), curses.A_REVERSE)
                    connwin.addstr(3, 2 + i * (2+max_len),f"state: {state}".center(max_len, " "), curses.A_NORMAL)
                    if conn["state"] == 0:
                        continue
                    connwin.addstr(4, 2 + i * (2+max_len),f"op: {op}".center(max_len, " "), curses.A_NORMAL)
                    connwin.addstr(5, 2 + i * (2+max_len),f"file: {filename}".center(max_len, " "), curses.A_NORMAL)
                    connwin.addstr(6, 2 + i * (2+max_len),f"bytes: {transferred}/{tsize}".center(max_len, " "), curses.A_NORMAL)
                    i+=1
            connwin.noutrefresh()
        except curses.error:
            pass

        # Testing window
        extrawin_x, extrawin_y = connwin_x + connwin_w, connwin_y
        extrawin_h, extrawin_w = connwin_h, win_w - connwin_w
        try:
            extrawin.erase()
            extrawin.box()
            extrawin.resize(extrawin_h, extrawin_w)
            extrawin.mvwin(extrawin_y, extrawin_x)

            extrawin.addstr(0, 2, " EXTRAS ", curses.A_BOLD)

            state_drop = "ENABLED" if ssftp_server.drop_packets else "DISABLED"
            state_delay = "ENABLED" if ssftp_server.delay_packets else "DISABLED"
            extrawin.addstr(2, 2, f" DROP PACKETS: {state_drop} ", curses.A_NORMAL)
            extrawin.addstr(3, 2, f" DELAY PACKETS: {state_delay} ", curses.A_NORMAL)

            # extrawin.addstr(extrawin_h-3, 1, f"  TOGGLE DROPPING: U".ljust(extrawin_w - 2), curses.A_STANDOUT)
            # extrawin.addstr(extrawin_h-2, 1, f"  TOGGLE DELAY: I".ljust(extrawin_w - 2), curses.A_STANDOUT)
            extrawin.noutrefresh()
        except curses.error:
            pass

        # Bottom bar
        footerwin_x, footerwin_y = logwin_x, extrawin_y + extrawin_h
        footerwin_h, footerwin_w = 1, win_w
        try:
            footerwin.erase()
            footerwin.resize(footerwin_h, footerwin_w)
            footerwin.mvwin(footerwin_y, footerwin_x)
            footer_text = "Q - QUIT   U - DROP PACKETS   I - DELAY PACKETS".center(footerwin_w-2)
            if len(footer_text) > footerwin_w:
                footer_text = footer_text[:footerwin_w-4] + "..."
            footerwin.addstr(0, 1, footer_text, curses.A_STANDOUT)
            footerwin.noutrefresh()
        except curses.error:
            pass

        # refreshing windows
        try:
            logwin.noutrefresh()
            logpad.refresh(vertical_scroll, horizontal_scroll, logpad_y, logpad_x, logpad_h, logpad_w)
        except curses.error:
            pass

        key = stdscr.getch()

        if key == ord('q'):
            ssftp_server.kill()
            break
        elif key == ord('u') or key == ord('U'):
            ssftp_server.drop_packets = not ssftp_server.drop_packets
        elif key == ord('i') or key == ord('I'):
            ssftp_server.delay_packets = not ssftp_server.delay_packets

        elif key == curses.KEY_UP and vertical_scroll > 0:
            vertical_scroll -= 1
        elif key == curses.KEY_DOWN:
            vertical_scroll += 1
        elif key == curses.KEY_LEFT and horizontal_scroll > 0:
            horizontal_scroll -= 1
        elif key == curses.KEY_RIGHT:
            horizontal_scroll += 1
        elif key == curses.KEY_RESIZE:
            continue

        curses.doupdate()
        sleep(1/60)


if __name__ == "__main__":


    curses.wrapper(main)
    # while True: pass
