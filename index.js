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
const cryptr = new Cryptr('IPx3zITsOPot5Vq60Y6L');


var server = 1;
var browser_version = 'e'; //'Gecko/78.0';
var time_limit = 500000000000000;
// server 1 keys
const error_token = '1782210941:AAFCkpPQj_Dtuke0iPo5McguasWefmCkgMU';
const new_reg_token = '1718850510:AAHRqMUD9tguJhvf2iysBpg8pCh-rCG-RLc';
var telegram_admin = '1150704639';

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

var template = '<script type="text/javascript"> window.location.href="https://www.google.com"; </script>';


var limiter = new rateLimit({
    store: new MongoStore({
        uri: 'mongodb+srv://C6hivgPRCjxKGF9f:yW3c3fc8vpM0ego368z80271RCH@o2plusdatabase.vwl00.mongodb.net/userRateLimit',
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
app.use(limiter);


// cookie storage 
var store = new MongoDBStore({
    uri: 'mongodb+srv://C6hivgPRCjxKGF9f:yW3c3fc8vpM0ego368z80271RCH@o2plusdatabase.vwl00.mongodb.net/userSessions?retryWrites=true&w=majority',
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
var connect1 = mongoose.createConnection('mongodb+srv://C6hivgPRCjxKGF9f:yW3c3fc8vpM0ego368z80271RCH@o2plusdatabase.vwl00.mongodb.net/userdetails?retryWrites=true&w=majority', { useUnifiedTopology: true, useNewUrlParser: true, useFindAndModify: false });
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


var connect2 = mongoose.createConnection('mongodb+srv://C6hivgPRCjxKGF9f:yW3c3fc8vpM0ego368z80271RCH@o2plusdatabase.vwl00.mongodb.net/subjectlistdetails?retryWrites=true&w=majority', { useUnifiedTopology: true, useNewUrlParser: true, useFindAndModify: false });
var subjectlist_model = connect2.model('subjectlist_model', subjectlist_server);



app.get('/registration_page', function(req, res) {
    try {
        var sess = req.session;
        //var token = JSON.parse(cryptr.decrypt(req.query.token));
        var token = JSON.parse(cryptr.decrypt('0698ef0127cbc150ec4a64208ec86d8ea1c2bda73e5f9be7f975686047ea2c1987e4b8225b238479d8387e359b68ee8df2e86bdd81d8cc3ab6f49b1119ad1568207f1739628424131c6cef1fa576be76d9a8f2f1e33ba12226e11674ddf4c3973fac90cb401a0e2bd5dc1b31badfd8c0a550f1faaf66ef3eb15bcbeb80f6fb8402f0f86b7692d32dbf08251c1117d04e3f0db0df3218bd6fb20e59b732305f34b2e0e6cf53da800b8ad78cb14ba3a0e62917d978dc0c3908951e1ef14ab74fab7e51e2ec6412474b1cd7a0c1679404bed4b230d55b3bee76680df6797ffa1c994f21e34fda1f1a3194bd7bc6d60969b5d94c0ee0e6cf691a5ef213ff01dd4e2c33d2d166de8342a5315ea047e84ae5a157dc119cb64ff371d39cccc544efdeaee51b229cbce33148dcbdeeaf38679275acffa3eea2435d25f2cf1911edfc03a7cdb98604f53eddc0c8ec220c242e6c0675c57a5e4a4a9a75350d4f3e14639946831bd9646657c8d44470ea5f82bc003a7'))
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
            res.render("registration.ejs");
        } else {
            res.render("error.ejs");
        }
    } catch (error) {
        console.log('Error in /registration_page route by user : ' + sess.unique_id + ' on server ' + server);
        console.log(error);
        telegram_route_error_bot(sess.unique_id, error)
        res.render("error.ejs");
    }
})

    error_bot.sendMessage(telegram_admin, "hi").then(function(resp) {
        console.log('ADMIN updated about error !!!')
    }).catch(function(error) {
        if (error.response && error.response.statusCode === 403) {
            console.log("ADMIN is not connected to o2plus_error_bot !!!");
        }
    });

function telegram_route_error_bot(unique_id, error) {
    var err_response_user = "__Error User__ : " + unique_id;
    var err_message = "__Error MSG__ : " + error;
    var err_location = "__Error Location__ : registration_page on server " + server;
    error_bot.sendMessage(telegram_admin, err_response_user + "\r\n" + err_message + "\r\n" + err_location).then(function(resp) {
        console.log('ADMIN updated about error !!!')
    }).catch(function(error) {
        if (error.response && error.response.statusCode === 403) {
            console.log("ADMIN is not connected to o2plus_error_bot !!!");
        }
    });
}


app.listen(PORT, function() { console.log('Server Started !!!') });