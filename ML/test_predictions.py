import urllib.request
import json
import sys

API_URL = "http://localhost:5000/predict"

test_cases = [
    # Phishing URL
    {
        "type": "url",
        "content": "http://malicious-phishing-site.ru/login",
        "expected": "Malicious"
    },
    # Legitimate URL
    {
        "type": "url",
        "content": "https://www.google.com",
        "expected": "Safe"
    },
    # Scam Email
    {
        "type": "email",
        "content": "Congratulations! You won a prize. Click here to claim now!",
        "expected": "Malicious"
    },
    # Legitimate Email
    {
        "type": "email",
        "content": "Hi Team, please find the attached project proposal for review.",
        "expected": "Safe"
    },
    # Scam SMS
    {
        "type": "sms",
        "content": "Your account is suspended. Verify now at http://bank-secure.ru",
        "expected": "Malicious"
    },
    # Legitimate SMS
    {
        "type": "sms",
        "content": "Hey, are we still meeting for lunch today?",
        "expected": "Safe"
    },
    # Scam Call Transcript
    {
        "type": "call",
        "content": "We have detected suspicious activity on your credit card. Call immediately at 1-800-555-0199.",
        "expected": "Malicious"
    },
    # Legitimate Call Transcript
    {
        "type": "call",
        "content": "Hello, this is a friendly reminder for your dentist appointment tomorrow at 10 AM.",
        "expected": "Safe"
    },
    # Safe IP
    {
        "type": "ip",
        "content": "192.168.1.50",
        "expected": "Safe"
    },
    # Malicious IP (random public IP in dataset)
    {
        "type": "ip",
        "content": "185.220.101.5",
        "expected": "Malicious"
    }
]

def run_tests():
    print("Starting integration tests on live API endpoint /predict...")
    print("=" * 70)
    passed_tests = 0

    for idx, case in enumerate(test_cases, 1):
        payload = {
            "type": case["type"],
            "content": case["content"]
        }
        
        req = urllib.request.Request(
            API_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                res_body = json.loads(response.read().decode("utf-8"))
                prediction = res_body.get("prediction")
                confidence = res_body.get("confidence")
                threat_level = res_body.get("threat_level")
                
                status = "PASS" if prediction == case["expected"] else "FAIL"
                if status == "PASS":
                    passed_tests += 1
                    
                print(f"Test #{idx} [{case['type'].upper()}]:")
                print(f"   Input    : {case['content'][:50]}...")
                print(f"   Expected : {case['expected']}")
                print(f"   Predicted: {prediction} (Confidence: {confidence}, Threat Level: {threat_level})")
                print(f"   Status   : {status}")
                print("-" * 70)
        except Exception as e:
            print(f"Test #{idx} [{case['type'].upper()}] FAILED with request error: {e}")
            print("-" * 70)

    print(f"Test Summary: {passed_tests}/{len(test_cases)} cases matched expected predictions.")
    if passed_tests == len(test_cases):
        print("ALL TESTS PASSED SUCCESSFULLY!")
        sys.exit(0)
    else:
        print("SOME TESTS DID NOT MATCH THE EXPECTED LABEL.")
        sys.exit(1)

if __name__ == "__main__":
    run_tests()
