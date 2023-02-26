const express = require("express");
const app = express();
const {promisify} = require('util');
const handlebars = require('handlebars');
const fs = require('fs');
const sessions = require('express-session');
const cookieParser = require("cookie-parser");
const pool = require("./config");
const bcrypt = require('bcrypt');
const {v4: uuidv4} = require('uuid');
const path = require('path');
const cors = require("cors");

app.use('/', express.static(path.join(__dirname, '/')));
app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(cookieParser());

const sessionDuration = 1000 * 60 * 5; // 5 minutes
app.use(sessions({
    name: "garamanteid",
    secret: "thisismysecrctekeyfhrgfgrfrty84fwir767",
    cookie: {
        maxAge: sessionDuration,
        httpOnly: false,
        secure: false
    },
    resave: false,
    saveUninitialized: true
}));

app.use(cors({
    origin: true,
    methods:['GET','POST','PUT','DELETE'],
    credentials: true,
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

app.listen(3033, () => {
    console.log("Garamante ID server listening on port 3033.");
});

app.get("/", async (req, res) => {
    const readFile = promisify(fs.readFile);
    let html = await readFile('login.html', 'utf8');
    let template = handlebars.compile(html);
    let data = {
        coming_url: req.body.service
    };
    let htmlToSend = template(data);
    res.send(htmlToSend);
});

app.get("/login", async (req, res) => {
    const readFile = promisify(fs.readFile);

    pool.getConnection()
        .then(conn => {
            conn.query("SELECT * FROM services WHERE id = ?", [req.query.service])
                .then(async (service) => {
                    conn.end();
                    if (service.length === 0) {
                        let html = await readFile('error.html', 'utf8');
                        res.send(html);
                    } else {
                        let html = await readFile('login.html', 'utf8');
                        let template = handlebars.compile(html);

                        let data = {
                            service_name: service[0].name,
                            service_url: service[0].home_url,
                        };
                        let htmlToSend = template(data);
                        res.send(htmlToSend);
                    }
                })
                .catch(async err => {
                    conn.end();
                    let html = await readFile('error.html', 'utf8');
                    console.log(err);
                    res.send(html);
                });
        });
});

app.post("/auth", async (req, res) => {
    let session = req.session;
    if (session.token) {
        res.redirect(301, req.body.service_url + "?auth=1");
    } else {
        pool.getConnection()
            .then(conn => {
                conn.query("SELECT * FROM users WHERE email = ?", [req.body.email])
                    .then((user) => {
                        conn.end();
                        if (user.length > 0) {
                            bcrypt
                                .compare(req.body.password, user[0].hashed_password)
                                .then(function (result) {
                                    if (result) {
                                        conn.query("SELECT token FROM tokens WHERE user_id = ? AND expiration_date > NOW();", [user[0].id])
                                            .then((token) => {
                                                if (token.length > 0) {
                                                    session.token = token[0].token;
                                                    res.redirect(301, req.body.service_url + "?auth=1");
                                                    conn.end();
                                                } else {
                                                    const token = uuidv4();
                                                    session.token = token;
                                                    conn.query("INSERT INTO tokens (user_id, token, days_duration) VALUES (?, '" + token + "', 5);", [user[0].id]);
                                                    res.redirect(301, req.body.service_url + "?auth=1");
                                                    conn.end();
                                                }
                                            })
                                            .catch(err => {
                                                res.redirect(301, "login.html?status=-3&service=" + req.body.service);
                                                console.log(err);
                                                conn.end();
                                            });
                                    } else {
                                        res.redirect(301, "login.html?status=-1&service=" + req.body.service);
                                    }
                                });
                        } else {
                            res.redirect(301, "login.html?status=-2&service=" + req.body.service);
                        }
                    })
                    .catch(err => {
                        conn.end();
                        res.redirect(301, "login.html?status=-3&service=" + req.body.service);
                    });
            })
            .catch(err => {
                res.redirect(301, "login.html?status=-3&service=" + req.body.service);
            });
    }
});

app.get("/token", async (req, res) => {
    let session = req.session;
    if (!session.token) {
        res.send({"error": "Token non trovato.", "status": -1});
    } else {
        res.send({"token": session.token, "status": 1});
    }
});

app.get("/me", async (req, res) => {
    pool.getConnection()
        .then(conn => {
            let token = req.headers['authorization'];
            conn.query("SELECT id, first_name, last_name, email, IF(tokens.expiration_date > NOW(), 1, 0) AS token_status FROM users INNER JOIN tokens ON users.id = tokens.user_id WHERE tokens.token = '" + token + "';")
                .then(async (token) => {
                    conn.end()
                    if (token.length > 0) {
                        if (token[0].token_status === 0) {
                            res.send({"error": "Token scaduto.", "status": 0});
                        } else {
                            res.send({"user": token[0], "status": 1});
                        }
                    } else {
                        res.send({"error": "Token non trovato.", "status": -1});
                    }
                })
                .catch(async err => {
                    conn.end();
                    console.log(err);
                    res.send({"error": "È stato riscontrato un errore.", "status": -2});
                });
        })
        .catch(async err => {
            console.log(err);
            res.send({"error": "È stato riscontrato un errore.", "status": -2});
        });
});