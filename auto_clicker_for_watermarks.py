import pyautogui
import time

def click_and_press_enter(interval=10):
    """Clicks at the center of the screen and presses 'Enter' every interval seconds."""
    try:
        while True:
            # Get the screen size
            screen_width, screen_height = pyautogui.size()
            
            # Calculate the center of the screen
            center_x = screen_width // 2
            center_y = screen_height // 2
            
            # Move the mouse to the center and click
            pyautogui.moveTo(center_x, center_y)
            pyautogui.click()
            
            # Press the 'Enter' key
            pyautogui.press('enter')
            
            print(f"Clicked and pressed 'Enter' at ({center_x}, {center_y}). Waiting for {interval} seconds.")
            
            # Wait for the specified interval
            time.sleep(interval)
    except KeyboardInterrupt:
        print("Bot stopped by user.")

# Run the bot
click_and_press_enter(5)


