from ai.category_detector import detect_category

complaint = """
I received a fraud call from 9876543210.

The scammer asked me to send money to:
fraudster@paytm
"""

print(detect_category(complaint))