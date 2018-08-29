Clone the repository using:-

git clone https://<<USERNAME>>@bitbucket.org/m4vr1ck/proxy-server.git

Go to the directory where the repository where the code is cloned.

Set 4 process environment variables before proceeding:-
WINDOWS:-
set UAM_URL="http://someurl:someport"
set BPM_URL="http://someurl:someport"
set PROXY_PORT="<<PORT>>"
set DMS_URL="http://someurl:someport"
set JWT_KEY="keyofyourchoice"

Once these variables are set, the server can be then started using either node app.js or nodemon app.js