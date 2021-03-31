require('dotenv').config();
var express = require('express');
const session = require('express-session');
const expressip = require('express-ip');
const path = require('path');
var bodyParser = require('body-parser');
var urlencodedParser = bodyParser.urlencoded({ extended: false });
var ejs = require('ejs');
var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var moment = require('moment');
const request = require('request');
const cryptoRandomString = require('crypto-random-string');
const PORT = process.env.PORT || 5000;
const helmet = require('helmet');
var pull = require('array-pull');
const ytdl = require('ytdl-core');
var ytpl = require('ytpl');
const getVideoId = require('get-video-id');
var MongoDBStore = require('connect-mongodb-session')(session);
var useragent = require('express-useragent');
const TelegramBot = require('node-telegram-bot-api');
const rateLimit = require("express-rate-limit");
var MongoStore = require('rate-limit-mongo');
const Cryptr = require('cryptr');
const cryptr = new Cryptr(process.env.CRYPT_KEY);


////////////////////////////////////////////////////////////////////////
var server = 1;
var browser_version = 'e'; //'Gecko/78.0';
var time_limit = 500000000000000;
////////////////////////////////////////////////////////////////////////



const error_token = cryptr.decrypt(process.env.ERROR_TOKEN);
const new_reg_token = cryptr.decrypt(process.env.NEWREG_TOKEN);
var telegram_admin = cryptr.decrypt(process.env.TELEGRAM_ADMIN);


const error_bot = new TelegramBot(error_token, { polling: true });
const new_reg_bot = new TelegramBot(new_reg_token, { polling: true });



var app = express();
app.use(useragent.express());
app.use(expressip().getIpInfoMiddleware);
app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/views'));

//app.use(
//    helmet({
//        contentSecurityPolicy: false,
//    })
//);

// redirect to any url except the present one

var template = '<script type="text/javascript"> window.location.href=window.location.origin+"/ratelimit"; </script>';


var limiter = new rateLimit({
    store: new MongoStore({
        uri: process.env.USERRATE_LIMIT,
        // should match windowMs
        collectionName: 'userRateLimit',
        expireTimeMs: 15 * 60 * 1000,
        errorHandler: console.error.bind(null, 'rate-limit-mongo')
        // see Configuration section for more options and details
    }),
    message: template,
    max: 100,
    // should match expireTimeMs
    windowMs: 15 * 60 * 1000
});

//  apply to all requests
app.set('trust proxy', 1);
app.use("/api/", limiter);


// cookie storage 
var store = new MongoDBStore({
    uri: process.env.USER_SESSIONS,
    collection: 'userSessions',
    expires: 1000 * 60 * 60 * 24, // cookie expire in mongo 24 hrs
    connectionOptions: {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        serverSelectionTimeoutMS: 10000
    }
});

store.on('error', function(error) {
    if (err) {
        console.log('CANT CONNECT TO MongoDBStore !!!');
        console.log(error);
    }
});

app.use(session({
    secret: 'U5EAM0SCAD37CLjpLp7a',
    cookieName: "OMWC",
    saveUninitialized: true,
    resave: true,
    store: store,
    cookie: {
        maxAge: 60 * 1000 // 60 seconds
    }
}));




var user_details_server = new Schema({
    username: {
        type: String,
        unique: true
    },
    password: String,
    branch: String,
    phonenumber: {
        type: Number,
        unique: true
    },
    phoneverified: Boolean,
    unique_id: {
        type: String,
        unique: true
    },
    userblocked: Boolean,
    video_watch_hour: Number,
    logincount: Number,
    lec_quality: String,
    points: Number,
    rank: Number,
    like: { type: [String], default: undefined },
    dislike: { type: [String], default: undefined },
    block_reason: String
}, {
    collection: 'user_details'
});
var connect1 = mongoose.createConnection(process.env.USER_DETAILS, { useUnifiedTopology: true, useNewUrlParser: true, useFindAndModify: false });
var user_details_model = connect1.model('user_details_model', user_details_server);

var subjectlist_server = new Schema({
    branch: String,
    subject: String,
    playlist: String,
    lec_num: Number,
    lec_name: String,
    lec_time: String,
    sublike: Number,
    subdislike: Number,
    views: Number,
    comments: [{
        commentor: String,
        rank: Number,
        commentor_msg: String
    }]
}, {
    collection: 'subjectlist_details'
});


var connect2 = mongoose.createConnection( process.env.SUBJECTLIST_DETAILS, { useUnifiedTopology: true, useNewUrlParser: true, useFindAndModify: false });
var subjectlist_model = connect2.model('subjectlist_model', subjectlist_server);



app.get('/api/registration_page', function(req, res) {
    try {
        var sess = req.session;
        //var token = JSON.parse(cryptr.decrypt(req.query.token));
        var token = JSON.parse(cryptr.decrypt('698ef0127cbc150ec4a64208ec86d8ea1c2bda73e5f9be7f975686047ea2c1987e4b8225b238479d8387e359b68ee8df2e86bdd81d8cc3ab6f49b1119ad1568207f1739628424131c6cef1fa576be76d9a8f2f1e33ba12226e11674ddf4c3973fac90cb401a0e2bd5dc1b31badfd8c0a550f1faaf66ef3eb15bcbeb80f6fb8402f0f86b7692d32dbf08251c1117d04e3f0db0df3218bd6fb20e59b732305f34b2e0e6cf53da800b8ad78cb14ba3a0e62917d978dc0c3908951e1ef14ab74fab7e51e2ec6412474b1cd7a0c1679404bed4b230d55b3bee76680df6797ffa1c994f21e34fda1f1a3194bd7bc6d60969b5d94c0ee0e6cf691a5ef213ff01dd4e2c33d2d166de8342a5315ea047e84ae5a157dc119cb64ff371d39cccc544efdeaee51b229cbce33148dcbdeeaf38679275acffa3eea2435d25f2cf1911edfc03a7cdb98604f53eddc0c8ec220c242e6c0675c57a5e4a4a9a75350d4f3e14639946831bd9646657c8d44470ea5f82bc003a7'))
        sess.browser_validity = req.useragent.source;
        sess.unique_id = token.unique_id;
        sess.user_ip = token.user_ip;
        sess.user_country = token.user_country;
        sess.user_city = token.user_city;
        sess.user_state = token.user_state;
        sess.build_product = token.build_product;
        sess.build_model = token.build_model;
        sess.build_manufacturer = token.build_manufacturer;
        var past_time = token.timestamp;
        var present_time = moment().format('x');
        var time_diff = present_time - past_time;
        if (sess.user_ip == req.ip && time_diff <= time_limit && sess.browser_validity.includes(browser_version)) {
            res.render("registration.ejs");
        } else {
            res.render("error.ejs");
        }
    } catch (error) {
        console.log('Error in /registration_page route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(error);
        var err_response_user = "__Error User__ : " + sess.unique_id;
        var err_message = "__Error MSG__ : " + error;
        var err_location = "__Error Location__ : registration_page on server " + server;
        var err_message = err_response_user + "\r\n" + err_message + "\r\n" + err_location;
        telegram_route_error_bot(err_message)
        res.render("error.ejs");
    }
})


app.post('/api/registration', urlencodedParser, function(req, res) {
    try {
        var sess = req.session;
        sess.browser_validity = req.useragent.source;
        if (sess.user_ip == req.ip && sess.browser_validity.includes(browser_version)) {
            var response = { username: req.body.username, password: req.body.password, branch: req.body.branch, phonenumber: req.body.phonenumber, phoneverified: false, unique_id: sess.unique_id, userblocked: true, video_watch_hour: 0, lec_quality: "highest", logincount: 0, like: [], dislike: [], points: 0, rank: 0, block_reason: "Nil" };
            user_details_model.create(response, function(err, result) {
                if (err) {
                    if (err.code === 11000) {
                        // duplicate 
                        var error_json = err.keyPattern;
                        var error_key = Object.keys(error_json);
                        var response_result = { form_dupname: "username" == error_key, form_dupdev: "unique_id" == error_key, form_dupphone: "phonenumber" == error_key, form_success: false };
                        console.log(response_result);
                        res.end(JSON.stringify(response_result));
                    }
                } else {
                    var username_update = "__Username__ : " + req.body.username;
                    var unique_id_update = "__Unique ID__ : " + sess.unique_id;
                    var user_state_update = "__State__ : " + sess.user_state;
                    new_reg_bot.sendMessage(telegram_admin, username_update + "\r\n" + unique_id_update + "\r\n" + user_state_update).then(function(resp) {
                        console.log('ADMIN informed about new User ' + req.body.username + '!!!')
                    }).catch(function(error) {
                        if (error.response && error.response.statusCode === 403) {
                            console.log("ADMIN is not connected to o2plus_newuser_bot !!!");
                        }
                    });
                    var response_result = { form_dupname: false, form_dupdev: false, form_dupphone: false, form_success: true };
                    res.end(JSON.stringify(response_result));
                }
            })
        } else {
            var response_result = { form_dupname: false, form_dupdev: false, form_dupphone: false, form_success: false };
            res.end(JSON.stringify(response_result));
        }
    } catch (error) {
        console.log('Error in /registration route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(error);
        var err_response_user = "__Error User__ : " + sess.unique_id;
        var err_message = "__Error MSG__ : " + error;
        var err_location = "__Error Location__ : registration on server " + server;
        var err_message = err_response_user + "\r\n" + err_message + "\r\n" + err_location;
        telegram_route_error_bot(err_message)
        var response_result = { form_dupname: false, form_dupdev: false, form_dupphone: false, form_success: false };
        res.end(JSON.stringify(response_result));
    }
})

app.get('/api/first_time_registration', function(req, res) {
    res.render("first_time_registration.ejs");
})


app.get('/api/login_page', function(req, res) {
    try {
        var sess = req.session;
        //var token = JSON.parse(cryptr.decrypt(req.query.token));
        var token = JSON.parse(cryptr.decrypt('698ef0127cbc150ec4a64208ec86d8ea1c2bda73e5f9be7f975686047ea2c1987e4b8225b238479d8387e359b68ee8df2e86bdd81d8cc3ab6f49b1119ad1568207f1739628424131c6cef1fa576be76d9a8f2f1e33ba12226e11674ddf4c3973fac90cb401a0e2bd5dc1b31badfd8c0a550f1faaf66ef3eb15bcbeb80f6fb8402f0f86b7692d32dbf08251c1117d04e3f0db0df3218bd6fb20e59b732305f34b2e0e6cf53da800b8ad78cb14ba3a0e62917d978dc0c3908951e1ef14ab74fab7e51e2ec6412474b1cd7a0c1679404bed4b230d55b3bee76680df6797ffa1c994f21e34fda1f1a3194bd7bc6d60969b5d94c0ee0e6cf691a5ef213ff01dd4e2c33d2d166de8342a5315ea047e84ae5a157dc119cb64ff371d39cccc544efdeaee51b229cbce33148dcbdeeaf38679275acffa3eea2435d25f2cf1911edfc03a7cdb98604f53eddc0c8ec220c242e6c0675c57a5e4a4a9a75350d4f3e14639946831bd9646657c8d44470ea5f82bc003a7'))
        sess.browser_validity = req.useragent.source;
        sess.unique_id = token.unique_id;
        sess.user_ip = token.user_ip;
        sess.user_country = token.user_country;
        sess.user_city = token.user_city;
        sess.user_state = token.user_state;
        sess.build_product = token.build_product;
        sess.build_model = token.build_model;
        sess.build_manufacturer = token.build_manufacturer;
        var past_time = token.timestamp;
        var present_time = moment().format('x');
        var time_diff = present_time - past_time;
        console.log(time_diff)
        if (sess.user_ip == req.ip && time_diff <= time_limit && sess.browser_validity.includes(browser_version)) {
            res.render("login.ejs");
        } else {
            res.render("error.ejs");
        }
    } catch (err) {
        console.log('Error in /login_page route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(err);
        var err_response_user = "__Error User__ : " + sess.unique_id;
        var err_message = "__Error MSG__ : " + err;
        var err_location = "__Error Location__ : login_page on server " + server;
        var err_message = err_response_user + "\r\n" + err_message + "\r\n" + err_location;
        telegram_route_error_bot(err_message);
        res.render("error.ejs");
    }
});


















function telegram_route_error_bot(message) {
    error_bot.sendMessage(telegram_admin, message).then(function(resp) {
        console.log('ADMIN updated !!!')
    }).catch(function(error) {
        if (error.response && error.response.statusCode === 403) {
            console.log("ADMIN is not connected to o2plus_error_bot !!!");
        }
    });
}


app.listen(PORT, function() { console.log('Server Started !!!') });