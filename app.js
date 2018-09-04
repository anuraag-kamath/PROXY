/*
    WELCOME TO THE WORLD OF PROXY
    WE WILL HANDLE ALL REQUESTS HERE
*/


//Express framework to handle all the requests and resposes along with the middleware to check login
const express = require("express")
//For making api calls to the actual back end-UAM,BPM and DMS
const fetch = require("node-fetch")
//Once authenticated, this library is used to generate the JWT used for further communications
const jsonwebtoken = require('jsonwebtoken');
//Library to parse the body from the request
const bodyparser = require('body-parser');
//Library to parse the cookie from the request
const cookieParser = require('cookie-parser');
var { userActivity } = require('./schemas/userActivity');
const { mongoose } = require('./db/database')

//initialing the express application
var app = express();

//initializing the middleware for the application

app.use(bodyparser.json({
    limit: '50mb'
}));

app.use(bodyparser.urlencoded({
    limit: '50mb',
    extended: true
}))

app.use(cookieParser())

//URLs for making the actual back-end calls
const uam_url = process.env.UAM_URL || "http://127.0.0.1:9100"
const bpm_url = process.env.BPM_URL || "http://127.0.0.1:9099"
const dms_url = process.env.DMS_URL || "http://127.0.0.1:9102"
const obj_url = process.env.OBJ_URL || "http://127.0.0.1:9103"
const logging_enabled = process.env.LOGGING_ENABLED || "N"
//the secret for generating the jwt_key. If nothing is provided in the process environment variable, default of alphabetagamma will be used!
const jwt_key = process.env.JWT_KEY || "alphabetagamma"

//Proxy server port
var port = process.env.PROXY_PORT || process.env.PORT || 9101

logger = (activity, url, params, status, userId, ipAddress, method, domain, token) => {
    if (logging_enabled == "Y") {
        if (userId.length > 0) {
            fetch(uam_url + '/user/' + userId, {
                method: "GET",
                credentials: "include",
                headers: {
                    "content-type": "application/json",
                    cookie: 'token=' + token + ';'

                }
            }).then((prom) => prom.text()).then((res1) => {
                if (res1 != undefined && res1 !== 'undefined') {
                    act = new userActivity({
                        activity, url, params, status, userId, user: res1.username, ipAddress, method, logDate: new Date(), domain
                    });
                    act.save();

                }


            })

        } else {
            act = new userActivity({
                activity, url, params, status, userId, user: "", ipAddress, method, logDate: new Date(), domain
            });
            act.save();

        }

    }
}

//Middleware just for logging purposes
app.use((req, res, next) => {
    var domain = ""
    var type = "resource";
    if (req.url.indexOf("/api") != -1) {
        type = "API";
    }
    var userId = "";
    if (req.cookies != undefined && req.cookies.token != undefined && req.cookies.token.length > 0) {
        try{
        userId = jsonwebtoken.verify(req.cookies.token, jwt_key).userId;
        }
        catch(e){
            req.cookies.token=null;
        
        }
    }
    logger(type, req.url, JSON.stringify(req.params), "success", userId, req.connection.remoteAddress, req.method, domain, req.cookies.token);
    next();
})


app.use(express.static(__dirname + "/public/resources/images"));

//Middleware to check whether user is authenticated
app.use((req, res, next) => {


    //req is modified with the domain of the API being called and the same is then removed from the req url
    if (req.url.indexOf("/api/uam") != -1) {
        req.apiDomain = "UAM"
        req.url = req.url.replace("/api/uam", "")
    } else if (req.url.indexOf("/api/bpm") != -1) {
        req.apiDomain = "BPM"
        req.url = req.url.replace("/api/bpm", "")
    } else if (req.url.indexOf("/api/dms") != -1) {
        req.apiDomain = "DMS"
        req.url = req.url.replace("/api/dms", "")
    } else if (req.url.indexOf("/api/objs") != -1) {
        req.apiDomain = "OBJ"
        req.url = req.url.replace("/api/objs", "")
    }
    //After checking domain for the API call, URL and method being set
    url = req.url;
    method = req.method;

    /*In case the request is for login related files, the request has to be served. In case the request is for any other thing, then the authentication
    has to be first checked and then only any other page,js,css,API can be served.*/
    if (url.indexOf("/login.html") != -1 ||
        url.indexOf("/login.css") != -1 ||
        url.indexOf("/login.js") != -1 ||
        url.indexOf("/login.png") != -1 ||
        url.indexOf("/bootstrap.min.css") != -1 ||
        (url == "/login" && method == "POST") ||
        (url == "/register" && method == "POST") ||
        (url.indexOf("/activate") != -1 && method == "POST") ||
        (url == "/resendActivationLink" && method == "POST") ||
        (url == "/resetPassword" && method == "POST") ||
        (url.indexOf("/activate") != -1 && method == "GET")) {
        try {
            //Check if the token is a valid token, if not throw an exception. If valid even though user requested login page, load the index.html instead
            jsonwebtoken.verify(req.cookies.token, jwt_key)
            //Bootstrap is an exception as it is necessary to be loaded
            if (url.indexOf("/bootstrap.min.css") != -1) {
                next()
            } else {
                res.redirect("/index.html")

            }
        } catch (e) {
            //exception caught when user was trying to land to login page, token is not valid, load the login html page.
            next()
        }
    }
    else if (req.cookies.token == undefined) {
        //Token is not set, redirect to login.html
        res.redirect("/login.html")
    }
    else {

        try {
            //Before performing any api action or serving any html,css,js file, authentication has to be checked.
            jsonwebtoken.verify(req.cookies.token, jwt_key)

            //List of files served by the Application. This is for verifying the role of the loggedin user.
            var wola = {
                workitems: ["/css/workitems.css", "/js/workitems.js", "/workitems.html"],
                process: ["/css/process.css", "/js/process.js", "/process.html"],
                listProcess: ["/css/listProcess.css", "/js/listProcess.js", "/listProcess.html"],
                listObjects: ["/css/listObjects.css", "/js/listObjects.js", "/listObjects.html"],
                objectViewer: ["/css/objectViewer.css", "/js/objectViewer.js", "/objectViewer.html"],
                objectBuilder: ["/css/object-builder.css", "/js/object-builder.js", "/object-builder.html"],
                listForms: ["/css/listForms.css", "/js/listForms.js", "/listForms.html"],
                listInstances: ["/css/listInstances.css", "/js/listInstances.js", "/listInstances.html"],
                index: ["/css/index.css", "/js/index.js", "/index.html", '/'],
                header: ["/css/header.css", "/js/header.js", "/header.html"],
                formBuilder: ["/css/main.css", "/js/main.js", "/formBuilder.html"],
                admin: ["/css/admin.css", "/js/admin.js", "/admin.html"],
                test: ["/tests/test.css", "/tests/test.js", "/tests/test.html"]

            }

            //fetch the roles of the logged in user
            fetch(uam_url + "/user/" + jsonwebtoken.verify(req.cookies.token, jwt_key).userId, {
                headers: {
                    "content-type": "application/json",
                    cookie: 'token=' + req.cookies.token + ';'
                }
            }).then((prom) => prom.json()).then((doc) => {

                if (doc != undefined) {
                    var roles = doc.roles;
                    var keys = Object.keys(wola);
                    var notApplicable = [];
                    for (var i = 0; i < keys.length; i++) {
                        found = false;
                        for (var j = 0; j < roles.length; j++) {
                            if (roles[j] == keys[i]) {
                                found = true;
                                break;
                            }
                        }
                        if (found == false) {
                            notApplicable.push(wola[keys[i]]);
                        }
                    }
                    var redirect = false;
                    for (var k = 0; k < notApplicable.length; k++) {
                        if (String(notApplicable[k]).indexOf(req.path) != -1) {
                            redirect = true;
                            //User is not authorized to view the given section/API
                            res.redirect('/notAuthorized.html');
                            break;
                        }
                    }
                    if (redirect == false) {

                        //in case the user has the right privileges, re-generate the jwt token and move on
                        token = jsonwebtoken.sign({ userId: doc._id }, jwt_key, {
                            expiresIn: '1H'
                        })
                        res.cookie('token', token, { httpOnly: true });
                        next();

                    }
                }
                else {
                    //user was not found!
                    res.redirect("/index.html")

                }

            })

        }
        catch (err) {
            //in case the token has invalidated.
            res.redirect("/login.html")
        }
    }

})

//Serving the HTML pages
app.all("*.html", (req, res) => {
    var url = "";
    //for login and notAuthorized, UAM serves up! rest all are served up in BPM
    if (String(req.url).indexOf("login.html") != -1 ||
        String(req.url).indexOf("notAuthorized.html") != -1) {
        url = uam_url;
    } else {
        url = bpm_url;
    }
    //Serving the HTML Pages
    fetch(url + req.url, {
        credentials: "include",
        method: "GET",
        headers: {
            "content-type": "application/json",
            cookie: 'token=' + req.cookies.token + ';'
        },
        credentials: 'include'

    }).then((prom) => prom.text())
        .then((proxyRes) => {
            res.writeHeader(200, { "Content-Type": "text/html" });
            res.write(proxyRes);
            res.end();
        });
})

app.all("*.png", (req, res) => {
    var url = "";
    //for login and notAuthorized, UAM serves up! rest all are served up in BPM
    if (String(req.url).indexOf("login.html") != -1 ||
        String(req.url).indexOf("notAuthorized.html") != -1) {
        url = uam_url;
    } else {
        url = bpm_url;
    }
    //Serving the HTML Pages
    fetch(url + req.url, {
        credentials: "include",
        method: "GET",
        headers: {
            "content-type": "application/json",
            cookie: 'token=' + req.cookies.token + ';'
        },
        credentials: 'include'

    }).then((prom) => prom.text())
        .then((proxyRes) => {
            res.writeHeader(200, { "Content-Type": "text/html" });
            res.write(proxyRes);
            res.end();
        });
})

//Serving the JS files
app.all("*.js", (req, res) => {
    var url = ""
    if (String(req.url).indexOf("login.js") != -1) {
        url = uam_url;
    } else {
        url = bpm_url;
    }
    //Serving the JS Files
    fetch(url + req.url, {
        method: "GET",
        headers: {
            "content-type": "application/json",
            cookie: 'token=' + req.cookies.token + ';'
        },
        credentials: 'include'
    }).then((prom) => prom.text())
        .then((proxyRes) => {
            res.writeHeader(200, { "Content-Type": "text/js" });
            res.write(proxyRes);
            res.end();
        })

})

//Serving the CSS files
app.all("*.css", (req, res) => {
    var url = ""
    if (String(req.url).indexOf("login.css") != -1 || String(req.url).indexOf("bootstrap.min.css") != -1) {
        url = uam_url;
    } else {
        url = bpm_url;
    }
    //Serving the CSS Files
    fetch(url + req.url, {
        method: "GET",
        headers: {
            "content-type": "application/json",
            cookie: 'token=' + req.cookies.token + ';'
        },
        credentials: 'include'
    }).then((prom) => prom.text())
        .then((proxyRes) => {
            res.writeHeader(200, { "Content-Type": "text/css" });
            res.write(proxyRes);
            res.end();

        })


})

//Just for PNG files.
app.use(express.static(__dirname + "/public"));

//For all the API Calls
app.all("*", (req, res, next) => {
    var domain = req.apiDomain;
    var method = req.method
    var url = ""

    if (domain == "UAM") {
        url = uam_url;
    } else if (domain == "BPM") {
        url = bpm_url;
    } else if (domain == "DMS") {
        url = dms_url;
    } else if (domain == "OBJ") {
        url = obj_url;
    } else {
        //Not an API call
        next()
    }
    console.log(url)
    console.log(domain)
    console.log(req.url);
    //url to be called
    proxy_url = req.url
    var body = {};

    //No body for Delete and Get API calls
    if (method != "DELETE" && method != "GET") {
        body = JSON.stringify(req.body);
    }


    if (method == "GET" || method == "DELETE") {

        fetch(url + proxy_url, {
            method,
            headers: {
                "content-type": "application/json",
                cookie: 'token=' + req.cookies.token + ';'
            }

        }).then((prom) => prom.text())
            .then((proxyRes) => {
                res.send(proxyRes)
            })
    }
    else {
        fetch(url + proxy_url, {
            method,
            headers: {
                "content-type": "application/json",
                cookie: 'token=' + req.cookies.token + ';'

            },
            credentials: 'include',
            body
        }).then((prom) => prom.text())
            .then((proxyRes) => {
                //In case the UAM responds with the token, setting the same in the response object

                if (proxyRes.indexOf("Activated") == -1 && JSON.parse(proxyRes).token != undefined) {
                    res.cookie('token', JSON.parse(proxyRes).token, { httpOnly: true }).send(proxyRes)

                } else {
                    res.send(proxyRes)
                }
            })
    }
})

//For all the calls that dont match any known URLs for the Application
app.use("*", (req, res, next) => {
    res.redirect("/index.html")
})

//Starting the server
app.listen(port, "0.0.0.0", () => {
    console.log("Proxy started at:-" + port);
})