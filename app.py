import requests
from flask import Flask, render_template, request
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import os

app = Flask(__name__)

# Vulnerability check functions
def check_xss(url):
    payload = "<script>alert('XSS')</script>"
    response = requests.get(url, params={"q": payload})
    if payload in response.text:
        return "Potential XSS vulnerability detected!"
    return "No XSS vulnerability found."

def check_sql_injection(url):
    payload = "' OR '1'='1", "1=1 --"," --"," AND 1=CONVERT(int, (SELECT @@version)) --"," UNION SELECT null, username, password FROM users --","' WAITFOR DELAY '00:00:05' --"," ; DROP TABLE users --"," AND EXISTS(SELECT * FROM users WHERE username = 'admin' AND password = 'password') --"," OR 1=1 LIMIT 1,1 --"," AND (SELECT COUNT(*) FROM users) > 0 --"
    response = requests.get(url, params={"q": payload})
    if "syntax error" in response.text or "SQL" in response.text:
        return "Potential SQL Injection vulnerability detected!"
    return "No SQL Injection vulnerability found."

def check_open_redirect(url):
    payload = "http://malicious.com"
    response = requests.get(url, params={"redirect": payload})
    if payload in response.text:
        return "Potential Open Redirect vulnerability detected!"
    return "No Open Redirect vulnerability found."

def check_insecure_http_methods(url):
    methods = ['TRACE', 'DELETE', 'PUT']
    results = {}
    for method in methods:
        try:
            response = requests.request(method, url)
            if response.status_code == 405:
                results[method] = "Method Not Allowed (safe)"
            else:
                results[method] = f"Method {method} is supported (potential issue)"
        except requests.exceptions.RequestException as e:
            results[method] = f"Error: {e}"
    return results

def generate_report(scan_results, filename="scan_report.pdf"):
    c = canvas.Canvas(filename, pagesize=letter)
    c.drawString(100, 750, "Vulnerability Scan Report")
    y_position = 730
    for result in scan_results:
        c.drawString(100, y_position, result)
        y_position -= 20
    c.save()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get("url")
    if not url:
        return render_template('index.html', error="Please provide a URL to scan.")

    xss_result = check_xss(url)
    sql_result = check_sql_injection(url)
    open_redirect_result = check_open_redirect(url)
    http_methods_result = check_insecure_http_methods(url)

    # Gather results into a single list
    scan_results = [
        f"XSS Test: {xss_result}",
        f"SQL Injection Test: {sql_result}",
        f"Open Redirect Test: {open_redirect_result}",
        f"Insecure HTTP Methods: {http_methods_result}"
    ]

    # Generate a PDF report
    report_filename = "scan_report.pdf"
    generate_report(scan_results, report_filename)

    # Return results with the option to download the PDF
    return render_template('index.html', results=scan_results, report_filename=report_filename, url=url)

if __name__ == '__main__':
    app.run(debug=True)
