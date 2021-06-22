import smtplib

EMAIL_ADDRESS = "tocasheri@gmail.com"
EMAIL_PASSWORD = "6980263685"

with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
    smtp.ehlo()
    smtp.starttls()
    smtp.ehlo()
    smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
    subject = "testing email"
    body="How are you my self?"
    msg=f'Subject:{subject}\n\nBody:{body}'
    smtp.sendmail(EMAIL_ADDRESS, "novasgiannis97@gmail.com", msg)
