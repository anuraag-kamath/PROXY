Clone the repository using:-

git clone https://<<USERNAME>>@bitbucket.org/m4vr1ck/proxy-server.git

Go to the directory where the repository where the code is cloned.

Set 4 process environment variables before proceeding:-
WINDOWS:-

set PROXY_URL=http://localhost:12000

set UAM_URL=http://localhost:12001

set BPM_URL=http://localhost:12002

set DMS_URL=http://localhost:12003

set OBJ_URL=http://localhost:12004

set JWT_KEY=omegathanos

set LOGGER_MONGODB_URL=mongodb://localhost:27017/logger

set LOGGING_ENABLED=Y


Once these variables are set, the server can be then started using either node app.js or nodemon app.js or pm2 start app.js --name proxy
