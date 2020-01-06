# MailCallback Library

This library is an evolution from the [mmcomm](https://www.github.com/cjungmann/mmcomm.git) project,
applying some things I learned there to a library that
can be easily extended by including in other projects
that will send and track emails sent through an already-setup
SMTP session.

## Dependencies

The share library depends on two other libraries, **OpenSSL** and
my own **code64**.  The **mailer** command additionally uses my
**readini** project to read a configuration file.

Install **OpenSSL** like this:

~~~sh
sudo apt-get install libssl-dev
~~~

My libraries should be cloned, built, and installed from my
GitHub account:

~~~sh
clone https://www.github.com/cjungmann/code64
clone https://www.github.com/cjungmann/readini

cd code64
make
sudo make install

cd ../readini
make
sudo make install
~~~

## Sub Project *mailer*

This small program uses the *libmailcb* library to send
emails from the command line.  It's not complete yet, so
some of the specifications are unfinished.

### Configuration file *mailer.conf*

While most of the settings like host, port, from, etc,
can be explictly set on the command line, it is much more
convenient to have a configuration file from which the 
settings can be read at run time.

By default and for now, in the absence of a specific
`-c config_file_name` command line option, **mailer**
will try to read configuration information from `./mailer.conf`.

The configuration file consists of sections labelled
with a word or phrase in square brackets, followed by
settings lines where the text up to the first space is
the tag, and what follows the spaces between the tag
and the rest of the text is the tag's value.

For example, `host     smtp.gmail.com` will have a tag
of *host* and a value of *smtp.gamil.clom*.  The
intervening spaces will be trimmed off, as well as any
trailing spaces, not to mention comments.

Here is a sample **mailer.conf** file:

~~~sh
[defaults]
logfile         ./mailer.log   # file to which, instead of stderr, log messages should be written.
default-account gmail          # account to use if no other account is specified


[gmail]
host     smtp.gmail.com
port     587
use_tls  on                    # Start TLS after HELO
user     gmail_user@gmail.com  # for the RCV FROM: of the email envelope
from     gmail_user@gmail.com  # for email header.  This may disappear
password abcdefghijklmnop      # Google-provided password to authorize two-factor authentication.

[gmail pop]
host     pop.gmail.com
type     pop                   # flag to initiate POP processing
port     995
use_tls  on
user     gmail_user@gmail.com
password abcdefghijklmnop
~~~


