# The Somewhat Simple File Transfer Protocol (SSFTP)
Not to be confused with the Secure Transfer Protocol, the Somewhat Simple File Transfer Protocol is a somewhat simple transfer protocol for transfering files over UDP with a simple connection mechanism inspired by TCP.

## Dependencies
For MacOS and Linux, there is no need to install anything, however, on windows, the python curses module is not supported, hence a module which provides support for it must be installed.

```shell
pip install windows-curses
```

## Running
Run the client through `clientapp.py` or run the server through `serverapp.py`. It is recommended to use a terminal window that spans at least half the screen. If elements in the window do not show up or do not show up completely, consider scaling the text with ctrl + (-).
```shell
# run the client
python3 clientapp.py

# run the server
python3 serverapp.py
```
