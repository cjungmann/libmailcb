# Online Resources For mmcomm Development

If not for helpful **man** pages and online pages from which
I needed to find explanation of the **man** pages, this utility
wouldn't exist.

As I write this README page, I haven't yet finished this command.
I continue to seek and learn details of the process of sending
SMTP mail, and the following pages have, or in the future may,
help me figure this whole thing out.

## SMTP Documentation

- [SMTP Standard Document](https://tools.ietf.org/html/rfc5321)  
  There is a lot here.  Links to specific sections are found below.

- [Enhanced SMTP Status Codes](https://tools.ietf.org/html/rfc3463)  
  In enhanced SMTP (greeting server with EHLO instead of HELO),
  there may be additional status information following the status
  code.  This document defines the protocol.

- [Mail Extension Parameters](https://www.iana.org/assignments/mail-parameters/mail-parameters.txt)
  This document contains a generous list of SMTP extension
  codes.  These extensions notify a user as to the features
  supported by the SMTP server, including 7BITMIME, CHUNKING,
  etc.

- [Bounced Email Reckoning](https://www.vtiger.com/docs/email-bounces-and-error-codes)  
  Undelivered emails should initiate some investigation.  This
  page discusses many reasons an email might bounce, and includes
  a table of SMTP error responses that help identify the type
  of bounce.

## POP3 Documentation

In order to responsibly send emails, one must ensure that refused
and bounced emails be strucken from the list to prevent repeated
submissions of email that will ultimately be refused.

Most of the work associated with establishing a connection to SMTP
servers is useful when connecting to a POP3 server.  The difference,
as far as I can tell right now, comes in the communication with
the server.  The following link(s) will illustrate and document
the nature of POP3 communication.

- [POP3 with telnet](https://www.shellhacks.com/retrieve-email-pop3-server-command-line/)

## Opening A Socket

The send email through SMTP, a socket must be opened.  One must
find the IP address of a domain before the socket can be opened.

- Getting the mail server's IP address through **getaddrinfo()**,
  a C function that uses various local and online resources to
  reconcile a domain.
  This [helpful **getaddrinfo** page](https://jameshfisher.com/2018/02/03/what-does-getaddrinfo-do/)
  helped me understand how to use **getaddrinfo**.

- [SMTP with telnet](https://www.wikihow.com/Send-Email-Using-Telnet)
  Understanding the sequence of communications with the SMTP
  server will inform that development of an automated process.

  The steps on this page only work for unsecure email.  That is,
  an SMTP conversation without using TLS.

- [SMTP with TLS](https://halon.io/blog/how-to-test-smtp-servers-using-the-command-line/)

- [Code Project SMTP Client with SSL/TSL](https://www.codeproject.com/Articles/98355/SMTP-Client-with-SSL-TLS)

- [Open SSL Client in C](https://aticleworld.com/ssl-server-client-using-openssl-in-c/)

- [Perhaps more useful; email/gmail specific](https://codevlog.com/gmailsmtp-gmail-com-using-c-programming-ssl/118)

- **netcat** is a linux command that opens a socket for reading or writing.
  Refer to its **man** page for documentation.

## Debugging Connections

- [Testing with OpenSSL and Telnet](https://www.stevenrombauts.be/2018/12/test-smtp-with-telnet-or-openssl/)
  Although not authoritative or complete, this page provides
  enough information to begin.

## Command Line Testing Server Greeting

It is easier to observe a server's reply in a terminal than by
writing or modifying a program to interpret the reply.  SMTP servers
can be used through **telnet** or **openssl**.  This section tries to
provide a little head-start to using these utilities to test SMTP
interactions.

- **telnet** can be used for unencrypted SMTP interactions, usually
  using port 25.

  ~~~sh
  user@computer: ~$ telnet smtp.gmail.com 587
  ~~~

- **openssl** can be used for encrypted interactions.

  ~~~sh
  user@computer: ~$ openssl s_client -connect smtp.gmail.com:587 -starttls smtp
  ~~~


## Email Sandbox

- [Amazon Simple Email Service](https://docs.aws.amazon.com/ses/latest/DeveloperGuide/Welcome.html)  
  I tried to use this.  It seemed to work once, but then not again.
  Perhaps I imagined the first time.  I may have to return to this
  for sandbox testing, but I couldn't figure out how to verify an
  email address and S3 bucket to receive emails.

  - This [SES Guide](https://blog.mailtrap.io/amazon-ses-explained/) offers
    a condensed set of instructions to getting a SES account up and
    running.

  - [TXT Record setup](https://www.namecheap.com/support/knowledgebase/article.aspx/317/2237/how-do-i-add-txtspfdkimdmarc-records-for-my-domain)
    gave me some problems that prompted me to call for support from
    NameCheap support.  The helpful support person directed me to the
    above link to help me understand the TXT record.  In short, when
    Amazon directs you to create a TXT record with a name `_amazonses.your_domain.com`,
    you set the host name to `_amazonses`, which is then a subdomain
    of `your_domain.com`.

- [PepiPost Sandbox](https://pepipost.com/blog/pepipost-sandbox/)
  I haven't used this yet, but it may be a sandbox I can use
  to see how another SMTP server responds.

## Interpreting Replys

- [SMTP Reply Codes](https://serversmtp.com/smtp-error/) explains codes likes 354, 250, etc.
- [Wiki on SMTP Reply Codes](https://en.wikipedia.org/wiki/List_of_SMTP_server_return_codes)
- [SMTP Standards about replies](https://tools.ietf.org/html/rfc5321#section-4.1.1.1)

## Structure of Email Message

- [Wiki SMTP Article](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol)

## Ensuring Completeness

There are so many scenarios for email, I need to test as many as possible
if I want this utility to be generally useful.

- [Amazon **S**imple **E**mail **S**ervice Mailbox Simulator](https://docs.aws.amazon.com/ses/latest/DeveloperGuide/mailbox-simulator.html)  
  This page shows SMTP responses to several types of email.  Use these
  email address (with SES, of course) to ensure likely cases can be 
  handled.