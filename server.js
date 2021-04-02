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
const rateLimit = require("express-rate-limit");
var MongoStore = require('rate-limit-mongo');
const Cryptr = require('cryptr');
const cryptr = new Cryptr(process.env.CRYPT_KEY);
const sendSeekable = require('send-seekable');
const https = require('https');

////////////////////////////////////////////////////////////////////////
var server = 1;
var browser_version = 'e'; //'Gecko/78.0';
var time_limit = 500000000000000;
var test_token = 'd4c3f6d71547808f3fe90669e14450147c02515360552105437383e73e2b6770b47c9b6b7946dc69d4cafee202631e4ba38b5f274cc574deebadac0ee5143992435e3e536ccd65807f2e1dea33564d91df745bac63829179809c9044549e564fbe6ab97d2d3cc06edf2e9aa061c5652e6301aaaaedeb041b1d185f464e91648ce650d0c977b2394fb9494b0cc940229dcb2380fa491d482d6582b9971cc1633575b45de08960910d03b2ced6e5c3255f7c48d81c00d44a1c007166522f92303729147f974934c4263d68be1249d8a4e9693d1306a3a20c661565fe3f88622fc764d1e2abb297dcd0ed9955d678fecfd118744e272d9233076db850ceecab4c93da90b597ab29d54ce4ab8f0d4525862a5034fd968599c99fd8ca575594bf6ba3c942c3d6065ae069c7fa181558c6727914d679584f85dae927990ae13850fbc5332848655be3a1eeeb82f5f78c86bd7335e4b3b1a30fb2c7556a23c4184a793d0ac73753dd27e0a36a128c'
////////////////////////////////////////////////////////////////////////



const error_token = cryptr.decrypt(process.env.ERROR_TOKEN);



var app = express();
app.use(useragent.express());
app.use(expressip().getIpInfoMiddleware);
app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/views'));
app.use(sendSeekable);
app.use(
    helmet({
        contentSecurityPolicy: false,
    })
);

app.use(function(req, res, next) {
    var url_schema = req.headers['x-forwarded-proto'];

    if (url_schema === 'https') {
        next();
    } else {
        res.redirect('https://' + req.headers.host + req.url);
    }
});

// redirect to any url except the present one

var template = '<script type="text/javascript"> window.location.href="about:blank"; </script>';


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
app.use(limiter);


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
        maxAge: 3 * 60 * 60 * 1000 // 60 seconds
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
    logincount: Number,
    video_watch_hour: Number,
    points: Number,
    rank: Number,
    token_coins: Number,
    like: { type: [String], default: undefined },
    dislike: { type: [String], default: undefined },
    userblocked: Boolean,
    block_reason: String,
    server: Number
}, {
    collection: 'user_details'
});
//username, password, branch, phonenumber, phoneverified, unique_id, logincount, video_watch_hour, points, rank, token_coins, like, dislike, userblocked, block_reason
var connect1 = mongoose.createConnection(process.env.USER_DETAILS, { useUnifiedTopology: true, useNewUrlParser: true, useFindAndModify: false });
var user_details_model = connect1.model('user_details_model', user_details_server);

var subjectlist_server = new Schema({
    branch: [String],
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


var connect2 = mongoose.createConnection(process.env.SUBJECTLIST_DETAILS, { useUnifiedTopology: true, useNewUrlParser: true, useFindAndModify: false });
var subjectlist_model = connect2.model('subjectlist_model', subjectlist_server);

ytpl("PLljuNwoG27OJgUKvLUeFB9tOlS2ZpmVUR").then(info => {
	var length = info.items.length;
	var i = 0;
	for (i=0; i < 40; i++){
		var response ={
			branch : [ 'ce', 'ch', 'cs', 'ec', 'ee' ,'in' , 'me'],
			subject : "mathematics",
			playlist : "PLljuNwoG27OJgUKvLUeFB9tOlS2ZpmVUR",
			lec_num: i+1,
			lec_name: info.items[i].title,
			lec_time: info.items[i].duration,
			sublike: 0,
			subdislike: 0,
			views: 0,
			comments: [],
		}
		subjectlist_model.create(response, function(err, result) {
			console.log(i);
		})
	} 
})


