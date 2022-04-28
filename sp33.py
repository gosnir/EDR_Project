import pynput.keyboard

def process_keys(KEY):
    print(type(KEY))


keyboard_listener = pynput.keyboard.Listener(on_press=process_keys)
with keyboard_listener:
    keyboard_listener.join()
