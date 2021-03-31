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
var browser_version = 'Gecko/78.0';
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

var template =  '<script type="text/javascript"> window.location.href="https://www.google.com"; </script>';


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
	if (err){
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
	try{
		var sess = req.session;
		res.send(sess)
	} catch (error) {
        console.log(error);
        res.render("error.ejs");
	}
})


app.listen(PORT, function() { console.log('Server Started !!!') });