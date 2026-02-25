import curses
import logging
import os
import ssftp
import ssftp_client as sclient
import socket
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

    ssftp_client = sclient.SSFTPClient(handler)

    headerwin = curses.newwin(1, 100, 0, 0)

    logwin = curses.newwin(10, 10, 0, 0)
    logpad = curses.newpad(MAX_LOGS, 500)  # hardcoding the length ig kek

    connwin = curses.newwin(10, 10, 0, 0)

    extrawin = curses.newwin(10, 10, 0, 0)

    footerwin = curses.newwin(1, 10, 0, 0)

    # Floating windows for certain operations
    connectwin = curses.newwin(1, 10, 0, 0)
    dwnwin = curses.newwin(1, 10, 0, 0)
    uplwin = curses.newwin(1, 10, 0, 0)

    floatingwin = None
    floatingwin_data = dict()

    # input stuff for windows
    input_buffer = ""

    def open_floating_window(win):
        nonlocal floatingwin
        nonlocal floatingwin_data
        nonlocal input_buffer
        floatingwin = win
        floatingwin_data = dict()
        input_buffer = ""

    def close_floating_window():
        nonlocal floatingwin
        nonlocal floatingwin_data
        nonlocal input_buffer
        floatingwin = None
        floatingwin_data = dict()
        input_buffer = ""

    while True:
        stdscr.erase()
        stdscr.noutrefresh()
        stdscr.nodelay(True)

        height, width = stdscr.getmaxyx()
        win_h, win_w = height - 2, width - 2

        if win_h <= 0 or win_w <= 0:
            continue

        key = stdscr.getch()

        # Draw headerwin
        app_title="SSFTP Client"
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
        connwin_h, connwin_w = win_h - logwin_h, win_w // 2
        try:
            connwin.erase()
            connwin.box()
            connwin.resize(connwin_h, connwin_w)
            connwin.mvwin(connwin_y, connwin_x)
            connwin.addstr(0, 2, " SERVER CONNECTION ", curses.A_BOLD)

            if ssftp_client.connection['addr'] is None:
                inner_text = "Press \"C\" to open a connection."
                connwin.addstr(connwin_h // 2, (connwin_w - len(inner_text)) // 2,inner_text, curses.A_DIM)
            else:
                conn = ssftp_client.connection
                addr = conn['addr']
                state = "IDLE" if conn["state"] == 0 else "IN TRANSFER"
                op = "..."
                if "op" in conn["options"]:
                    op = "DWN" if conn["options"]["op"] == ssftp.OPCODE.DWN.value.get_int() else "UPL"
                filename = "..." if "filename" not in conn["options"] else conn["options"]["filename"]
                block = None if "block" not in conn["options"] else int(conn["options"]["block"])
                blksize = None if "blksize" not in conn["options"] else int(conn["options"]["blksize"])
                tsize = "..." if "tsize" not in conn["options"] else int(conn["options"]["tsize"])
                transferred = "..." if block is None or blksize is None else min(block * blksize, tsize)

                max_len = 30
                # logs.append(str(addr)))
                connwin.addstr(2, 2 + (2+max_len),f"{addr[0]}:{addr[1]}".center(max_len, " "), curses.A_REVERSE)
                connwin.addstr(3, 2 + (2+max_len),f"state: {state}".center(max_len, " "), curses.A_NORMAL)
                if conn["state"] == 0:
                    pass
                else:
                    connwin.addstr(4, 2 + (2+max_len),f"op: {op}".center(max_len, " "), curses.A_NORMAL)
                    connwin.addstr(5, 2 + (2+max_len),f"file: {filename}".center(max_len, " "), curses.A_NORMAL)
                    connwin.addstr(6, 2 + (2+max_len),f"bytes: {transferred}/{tsize}".center(max_len, " "), curses.A_NORMAL)
            connwin.noutrefresh()
        except curses.error:
            pass

        # Extras window
        extrawin_x, extrawin_y = connwin_x + connwin_w, connwin_y
        extrawin_h, extrawin_w = connwin_h, win_w - connwin_w
        try:
            extrawin.erase()
            extrawin.box()
            extrawin.resize(extrawin_h, extrawin_w)
            extrawin.mvwin(extrawin_y, extrawin_x)

            extrawin.addstr(0, 2, " EXTRAS ", curses.A_BOLD)

            state_drop = "ENABLED" if ssftp_client.drop_packets else "DISABLED"
            state_delay = "ENABLED" if ssftp_client.delay_packets else "DISABLED"
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
            footer_text1 = "X - DISCONNECT   Q - QUIT   U - DROP PACKETS   I - DELAY PACKETS   C - CONNECT   W - READ   R - DOWNLOAD   F1 - CLOSE MENU".center(footerwin_w-2)
            if len(footer_text1) > footerwin_w:
                footer_text1 = footer_text1[:footerwin_w-4] + "..."
            footerwin.addstr(0, 1, footer_text1, curses.A_STANDOUT)
            footerwin.noutrefresh()
        except curses.error as e:
            pass

        # for each floating window
        try:
            if floatingwin == connectwin:
                connectwin_h, connectwin_w = 10, win_w//2
                connectwin_x, connectwin_y = (win_w-connectwin_w)//2, (win_h-connectwin_h)//2
                connectwin.resize(connectwin_h, connectwin_w)
                connectwin.mvwin(connectwin_y, connectwin_x)
                connectwin.box()
                connectwin.addstr(0, 2, " CONNECT TO SERVER ", curses.A_BOLD)
                connectwin.addstr(2, 4, "Enter server address (ip:port):")
                connectwin.addstr(3, 4, input_buffer.ljust(connectwin_w-8), curses.A_STANDOUT)
                if "err_msg" in floatingwin_data:
                    connectwin.addstr(5, 4, floatingwin_data["err_msg"], curses.A_ITALIC)
                if "err_msg_cd" in floatingwin_data:
                    floatingwin_data["err_msg_cd"] -= 1
                    if floatingwin_data["err_msg_cd"] <= 0 and "err_msg" in floatingwin_data:
                        floatingwin_data["err_msg"] = " "*(connectwin_w-8)

                def is_valid_ip(address):
                    try:
                        ip, port_str = address.rsplit(':', 1)
                        socket.inet_aton(ip)
                        if 0 <= int(port_str) <= 65535:
                            return True
                        return False
                    except (socket.error, ValueError):
                        return False

                if key in [ord(f'{x}') for x in range(0, 10)] + [ord(':'), ord('.')]:
                    input_buffer += chr(key)
                elif key == curses.KEY_F1:
                    close_floating_window()
                elif key == curses.KEY_BACKSPACE:
                    input_buffer = input_buffer[:-1]
                elif key in (ord('\n'), ord('\r')):
                    if not is_valid_ip(input_buffer):
                        floatingwin_data["err_msg"] = "Invalid IPv4 address."
                        floatingwin_data["err_msg_cd"] = 60 * 2
                    else:
                        ip, port = input_buffer.rsplit(':', 1)
                        addr = (ip, int(port))
                        Thread(target=lambda:ssftp_client.connect_to(addr),daemon=True).start()
                        close_floating_window()

                # sort of like a prevent default action
                if floatingwin is not None:
                    key = None

            elif floatingwin == dwnwin:
                dwnwin_h, dwnwin_w = 10, win_w//2
                dwnwin_x, dwnwin_y = (win_w-dwnwin_w)//2, (win_h-dwnwin_h)//2
                dwnwin.resize(dwnwin_h, dwnwin_w)
                dwnwin.mvwin(dwnwin_y, dwnwin_x)
                dwnwin.box()
                dwnwin.addstr(0, 2, " DOWNLOAD FILE ", curses.A_BOLD)
                dwnwin.addstr(2, 4, "Enter name of file to download:")
                dwnwin.addstr(3, 4, input_buffer.ljust(dwnwin_w-8), curses.A_STANDOUT)

                if 32 <= key <= 126:  # valid keys for input
                    input_buffer += chr(key)
                elif key == curses.KEY_F1:
                    close_floating_window()
                elif key == curses.KEY_BACKSPACE:
                    input_buffer = input_buffer[:-1]
                elif key in (ord('\n'), ord('\r')):
                    def fn(): ssftp_client.send_dwn(input_buffer, ssftp.TRANSFER_MODES.octet)
                    Thread(target=fn, daemon=True).start()
                    close_floating_window()

                # sort of like a prevent default action
                if floatingwin is not None:
                    key = None

            elif floatingwin == uplwin:
                uplwin_h, uplwin_w = 2*win_h//3, win_w//2
                uplwin_x, uplwin_y = (win_w-uplwin_w)//2, (win_h-uplwin_h)//2
                uplwin.resize(uplwin_h, uplwin_w)
                uplwin.mvwin(uplwin_y, uplwin_x)
                uplwin.box()
                uplwin.addstr(0, 2, " UPLOAD FILE ", curses.A_BOLD)
                uplwin.addstr(2, 4, "Select file to upload.")

                # uplwin.addstr(3, 4, input_buffer.ljust(uplwin_w-8), curses.A_STANDOUT)
                if "selection" not in floatingwin_data:
                    floatingwin_data["selection"] = 0

                files = [file for file in os.listdir('.') if os.path.isfile(file)]
                for i, file in enumerate(files):
                    prefix = "  "
                    if floatingwin_data["selection"] == i:
                        prefix = "> "
                    uplwin.addstr(3+i, 6, f'{prefix} {file}', curses.A_NORMAL)

                if key == curses.KEY_F1:
                    close_floating_window()
                elif key in (ord('\n'), ord('\r')):
                    selection = floatingwin_data["selection"]
                    selected_file = files[selection] 
                    def fn(): ssftp_client.send_upl(selected_file, ssftp.TRANSFER_MODES.octet)
                    Thread(target=fn, daemon=True).start()
                    close_floating_window()
                elif key == curses.KEY_UP:
                    if floatingwin_data["selection"] > 0: floatingwin_data["selection"] -= 1
                elif key == curses.KEY_DOWN:
                    if floatingwin_data["selection"] < len(files): floatingwin_data["selection"] += 1

                # sort of like a prevent default action
                if floatingwin is not None:
                    key = None

        except curses.error:
            pass

        # refreshing windows
        try:
            logwin.noutrefresh()
            logpad.refresh(vertical_scroll, horizontal_scroll, logpad_y, logpad_x, logpad_h, logpad_w)
            if floatingwin is not None:
                floatingwin.noutrefresh()
        except curses.error:
            pass

        if key == ord('q') or key == ord('Q'):
            ssftp_client.kill()
            break
        elif key == ord('x') or key == ord('X'):
            ssftp_client.graceful_disconnect()
        elif key == ord('u') or key == ord('U'):
            ssftp_client.drop_packets = not ssftp_client.drop_packets
        elif key == ord('i') or key == ord('I'):
            ssftp_client.delay_packets = not ssftp_client.delay_packets

        elif key == ord('c') or key == ord('C'):
            open_floating_window(connectwin)
        elif key == ord('r') or key == ord('R'):
            if ssftp_client.connection['addr'] is None:
                logs.append("Please open a connection first.")
                continue
            open_floating_window(dwnwin)
        elif key == ord('w') or key == ord('W'):
            if ssftp_client.connection['addr'] is None:
                logs.append("Please open a connection first.")
                continue
            open_floating_window(uplwin)

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
